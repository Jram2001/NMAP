/**
 * TCP Header Options Builders
 * 
 * TCP options extend the basic 20-byte header to provide additional functionality.
 * Each option has a specific format defined in various RFCs.
 * 
 * Option Format (for options with length > 1):
 * +--------+--------+--------+--------+
 * |  Kind  | Length |    Data...      |
 * +--------+--------+--------+--------+
 * 
 * Kind: 1 byte identifying the option type
 * Length: 1 byte indicating total option length (including Kind and Length bytes)
 * Data: Variable length option-specific data
 */

/**
 * End of Option List (RFC 793)
 * Kind: 0, Length: 1 byte
 * 
 * Marks the end of the options list. All remaining option space should be padding.
 * Must be the last option if present.
 * 
 * @returns {Buffer} Single byte buffer containing EOL option
 */
function optEOL() {
    return Buffer.from([0x00]); // Kind = 0
}

/**
 * No Operation (RFC 793) 
 * Kind: 1, Length: 1 byte
 * 
 * Used for padding between options to align them on word boundaries.
 * Can appear multiple times and anywhere in the options.
 * 
 * @returns {Buffer} Single byte buffer containing NOP option
 */
function optNOP() {
    return Buffer.from([0x01]); // Kind = 1
}

/**
 * Maximum Segment Size (RFC 793)
 * Kind: 2, Length: 4 bytes
 * 
 * Specifies the maximum TCP segment size this host can receive.
 * Only valid in SYN packets (connection establishment).
 * If not present, assumes 536 bytes (minimum required).
 * 
 * Format: [Kind=2][Length=4][MSS (16-bit)]
 * 
 * @param {number} mss - Maximum segment size (0-65535)
 * @returns {Buffer} 4-byte buffer containing MSS option
 */
function optMSS(mss) {
    const b = Buffer.alloc(4);
    b[0] = 0x02;                    // Kind = 2 (MSS)
    b[1] = 4;                       // Length = 4 bytes total
    b.writeUInt16BE(mss, 2);        // MSS value (16-bit, network byte order)
    return b;
}

/**
 * Window Scale (RFC 7323, formerly RFC 1323)
 * Kind: 3, Length: 3 bytes
 * 
 * Allows TCP window sizes larger than 65535 bytes by specifying a scale factor.
 * Actual window = advertised_window << scale_factor
 * Only valid in SYN packets. Scale factor range: 0-14.
 * 
 * Format: [Kind=3][Length=3][Scale Factor (8-bit)]
 * 
 * @param {number} shift - Scale factor (0-14, values > 14 are clamped)
 * @returns {Buffer} 3-byte buffer containing window scale option
 */
function optWScale(shift) {
    const s = Buffer.alloc(3);
    s[0] = 0x03;                    // Kind = 3 (Window Scale)
    s[1] = 3;                       // Length = 3 bytes total
    s[2] = shift & 0xff;            // Scale factor (clamped to 8 bits)
    return s;
}

/**
 * Selective Acknowledgment Permitted (RFC 2018)
 * Kind: 4, Length: 2 bytes
 * 
 * Indicates that the sender supports SACK (Selective ACK).
 * Only sent in SYN packets during connection establishment.
 * If both sides send this, they can use SACK blocks in subsequent packets.
 * 
 * Format: [Kind=4][Length=2]
 * 
 * @returns {Buffer} 2-byte buffer containing SACK permitted option
 */
function optSACK() {
    return Buffer.from([0x04, 0x02]); // Kind = 4, Length = 2
}

/**
 * Timestamp (RFC 7323, formerly RFC 1323)
 * Kind: 8, Length: 10 bytes
 * 
 * Provides two functions:
 * 1. Round-trip time measurement (RTTM)
 * 2. Protection Against Wrapped Sequences (PAWS)
 * 
 * TSval: Timestamp value from sender
 * TSecr: Echo of timestamp received from peer (0 in SYN packets)
 * 
 * Format: [Kind=8][Length=10][TSval (32-bit)][TSecr (32-bit)]
 * 
 * @param {number} tsval - Timestamp value (default: 0xFFFFFFFF for debugging)
 * @param {number} tsecr - Timestamp echo reply (default: 0)
 * @returns {Buffer} 10-byte buffer containing timestamp option
 */
function optTimestamp(tsval = 0xFFFFFFFF, tsecr = 0) {
    const b = Buffer.alloc(10);
    b[0] = 0x08;                    // Kind = 8 (Timestamp)
    b[1] = 10;                      // Length = 10 bytes total

    // Use unsigned right shift (>>>) to ensure 32-bit unsigned values
    b.writeUInt32BE(tsval >>> 0, 2); // TSval at offset 2-5
    b.writeUInt32BE(tsecr >>> 0, 6); // TSecr at offset 6-9
    return b;
}

/**
 * TCP Options Padding Function
 * 
 * TCP options must be padded so that the total header length is a multiple 
 * of 4 bytes (32 bits). This is required because the TCP Data Offset field
 * specifies header length in 32-bit words.
 * 
 * Padding Strategy:
 * - Use NOP (0x01) bytes for padding (recommended approach)
 * - Alternative: Use EOL (0x00) followed by zeros, but NOP is more flexible
 * 
 * @param {Buffer} buf - Buffer containing TCP options
 * @returns {Buffer} Padded buffer with length multiple of 4
 */
function optPadding(buf) {
    const rem = buf.length % 4;     // Calculate remainder when divided by 4

    if (rem === 0) {
        return buf;                 // Already aligned, no padding needed
    }

    const padLength = 4 - rem;      // Number of padding bytes needed (1-3)

    // Pad with NOP options (0x01) - this is the standard approach
    // Using NOP instead of zeros makes the padding valid TCP options
    return Buffer.concat([buf, Buffer.alloc(padLength, 0x01)]);
}

/*
 * USAGE EXAMPLES:
 * 
 * // Basic SYN packet options
 * const synOptions = Buffer.concat([
 *     optMSS(1460),           // Announce MSS of 1460 bytes
 *     optWScale(7),           // Window scaling factor of 7 (128x multiplier)
 *     optSACK(),              // Enable SACK support
 *     optTimestamp()          // Enable timestamps
 * ]);
 * const paddedOptions = optPadding(synOptions);
 * 
 * // Simple padding example
 * const simpleOpts = Buffer.concat([optMSS(1460)]); // 4 bytes, no padding needed
 * const needsPadding = Buffer.concat([optWScale(3)]); // 3 bytes, needs 1 NOP
 * 
 * IMPORTANT NOTES:
 * 
 * 1. Option Order: While not strictly required, common practice is:
 *    MSS, Window Scale, SACK Permitted, Timestamp
 * 
 * 2. SYN-only Options: MSS, Window Scale, and SACK Permitted are typically
 *    only sent in SYN packets during connection establishment.
 * 
 * 3. Timestamp Usage: TSval should be a monotonically increasing value
 *    (often system uptime). TSecr should echo the most recent TSval received.
 * 
 * 4. Maximum Options Length: Total options cannot exceed 40 bytes
 *    (TCP header max is 60 bytes, base header is 20 bytes).
 * 
 * 5. Padding with NOP: Using NOP (0x01) for padding is preferred over
 *    EOL (0x00) because NOP can appear anywhere and multiple times.
 * 
 * 6. Window Scale Limitations: Scale factors > 14 are not useful because
 *    they would result in window sizes > 1GB, which is impractical.
 */

module.exports = { optEOL, optNOP, optMSS, optWScale, optSACK, optTimestamp, optPadding }