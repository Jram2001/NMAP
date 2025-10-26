/**
 * Converts an IPv4 address string to a 4-byte buffer
 * Example: "192.168.1.1" -> Buffer([192, 168, 1, 1])
 * 
 * @param {string} ip - IPv4 address in dotted decimal notation
 * @returns {Buffer} - 4-byte buffer representing the IP address
 */
function ipToBuffer(ip) {
    console.log(ip, 'ip')
    // Split IP by dots and convert each octet to integer
    // FIXED: parseInt is a global function, not a method of string
    return Buffer.from(ip.split('.').map(n => parseInt(n, 10)));
}
/**
 * Calculates TCP checksum using pseudo-header approach (RFC 793)
 * 
 * TCP Pseudo-header structure:
 * +--------+--------+--------+--------+
 * |           Source Address          |
 * +--------+--------+--------+--------+
 * |         Destination Address       |
 * +--------+--------+--------+--------+
 * | zero   |  PTCL  |    TCP Length   |
 * +--------+--------+--------+--------+
 * 
 * The checksum is calculated over:
 * 1. Pseudo-header (12 bytes)
 * 2. TCP header (with checksum field set to 0)
 * 3. TCP data
 * 
 * @param {string} srcIp - Source IP address
 * @param {string} destIp - Destination IP address  
 * @param {Buffer} tcpBuffer - Complete TCP segment (header + data)
 * @returns {number} - 16-bit checksum value
 */
function tcpCheckSum(srcIp, destIp, tcpBuffer) {
    // STEP 1: Build pseudo-header (12 bytes total)
    const pseudoHeader = Buffer.alloc(12);

    // Bytes 0-3: Source IP address
    const srcIpBuffer = ipToBuffer(srcIp);
    srcIpBuffer.copy(pseudoHeader, 0);

    // Bytes 4-7: Destination IP address  
    const destIpBuffer = ipToBuffer(destIp);
    destIpBuffer.copy(pseudoHeader, 4);

    // Byte 8: Zero padding
    pseudoHeader.writeUInt8(0x00, 8);

    // Byte 9: Protocol number (6 for TCP)
    pseudoHeader.writeUInt8(0x06, 9);

    // Bytes 10-11: TCP segment length (header + data)
    pseudoHeader.writeUInt16BE(tcpBuffer.length, 10);

    // STEP 2: Concatenate pseudo-header with TCP segment
    const checksumData = Buffer.concat([pseudoHeader, tcpBuffer]);
    // STEP 3: Calculate one's complement sum
    const sum = onesComplementSum(checksumData);

    // STEP 4: Return one's complement of the sum (bitwise NOT)
    return (~sum) & 0xFFFF;
}
/**
 * Calculates the one's complement sum used in Internet checksums
 * 
 * Algorithm:
 * 1. Sum all 16-bit words in the buffer
 * 2. Add any carry bits back into the sum (fold carries)
 * 3. Handle odd-length buffers by padding with zero
 * 
 * This is the standard Internet checksum algorithm used by TCP, UDP, IP, etc.
 * 
 * @param {Buffer} buf - Buffer to calculate checksum over
 * @returns {number} - 16-bit one's complement sum
 */
function onesComplementSum(buf) {
    let sum = 0;

    // Process buffer in 16-bit words (2 bytes at a time)
    for (let i = 0; i < buf.length; i += 2) {
        let word;

        if (i + 1 < buf.length) {
            // Normal case: we have both bytes for a complete 16-bit word
            // Combine high byte (buf[i]) and low byte (buf[i+1])
            word = (buf[i] << 8) + buf[i + 1];
        } else {
            // Odd-length buffer: pad the last byte with zero
            // FIXED: Handle odd-length buffers properly
            word = buf[i] << 8; // High byte only, low byte is implicitly 0
        }

        // Add word to running sum
        sum += word;

        // Fold any carry bits back into the sum
        // This handles cases where sum exceeds 16 bits
        // Keep folding until no more carries (important for multiple carries)
        while (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >>> 16);
        }
    }

    return sum;
}


module.exports = { tcpCheckSum }