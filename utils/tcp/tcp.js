const { optPadding } = require("./option-bulder");
const { tcpCheckSum } = require("./tcp-checksum");
/**
 * Builds a complete TCP packet with proper header structure and checksum
 * 
 * TCP Header Structure (RFC 793):
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data |           |U|A|P|R|S|F|                               |
 * | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 * |       |           |G|K|H|T|N|N|                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
function Encode(
    srcIp,           // Source IP address (used for checksum calculation)
    destIp,          // Destination IP address (used for checksum calculation)
    srcPort,         // Source port number (16-bit)
    destPort,        // Destination port number (16-bit)
    seqNumber = 0,   // Sequence number (32-bit) - tracks bytes sent
    ackNumber = 0,   // Acknowledgment number (32-bit) - next expected sequence number
    flags = {},      // TCP flags object: {fin, syn, rst, psh, ack, urg, ece, cwr}
    windowSize = 65535,      // Receive window size (16-bit) - flow control
    urgentPointer = 0,       // Urgent pointer (16-bit) - points to urgent data
    options = Buffer.alloc(0), // TCP options (variable length)
    data = Buffer.alloc(0)     // Payload data
) {
    // STEP 1: Prepare options with proper padding
    // TCP options must be padded to ensure header length is multiple of 4 bytes
    // This is required because the data offset field counts in 32-bit words
    let paddedOptions = optPadding(options, 'options');
    // STEP 2: Allocate header buffer
    // Base TCP header is 20 bytes + padded options length
    // CRITICAL: Use paddedOptions.length, not options.length for correct allocation
    const header = Buffer.alloc(20 + paddedOptions.length);
    // STEP 3: Write basic header fields (bytes 0-11)
    // All multi-byte values are in network byte order (big-endian)
    header.writeUInt16BE(srcPort, 0);    // Bytes 0-1: Source Port
    header.writeUInt16BE(destPort, 2);   // Bytes 2-3: Destination Port
    header.writeUInt32BE(seqNumber, 4);  // Bytes 4-7: Sequence Number
    header.writeUInt32BE(ackNumber, 8);  // Bytes 8-11: Acknowledgment Number

    // STEP 4: Build the data offset and flags field (bytes 12-13)
    // Data offset = header length in 32-bit words (minimum 5 for 20-byte header)
    // CRITICAL: Use paddedOptions.length to get actual header size
    let dataOffset = (20 + paddedOptions.length) / 4;

    // Data offset occupies upper 4 bits, reserved field is next 3 bits (set to 0)
    let offsetAndReserved = dataOffset << 12;

    // Build TCP flags in lower 8 bits
    // Each flag corresponds to a specific bit position
    let flagBits = 0;
    if (flags.fin) flagBits |= 0x01;  // Bit 0: FIN - Connection termination
    if (flags.syn) flagBits |= 0x02;  // Bit 1: SYN - Synchronize sequence numbers
    if (flags.rst) flagBits |= 0x04;  // Bit 2: RST - Reset connection
    if (flags.psh) flagBits |= 0x08;  // Bit 3: PSH - Push data to application
    if (flags.ack) flagBits |= 0x10;  // Bit 4: ACK - Acknowledgment field valid
    if (flags.urg) flagBits |= 0x20;  // Bit 5: URG - Urgent pointer valid
    if (flags.ece) flagBits |= 0x40;  // Bit 6: ECE - ECN Echo (congestion control)
    if (flags.cwr) flagBits |= 0x80;  // Bit 7: CWR - Congestion Window Reduced

    // Combine data offset (upper 4 bits) with flags (lower 8 bits)
    header.writeUInt16BE(offsetAndReserved | flagBits, 12);

    // STEP 5: Write remaining header fields (bytes 14-19)
    header.writeUInt16BE(windowSize, 14);      // Bytes 14-15: Window Size
    // Checksum at bytes 16-17 will be calculated later (initially 0)
    header.writeUInt16BE(urgentPointer, 18);   // Bytes 18-19: Urgent Pointer   

    // STEP 6: Copy padded options to header
    // Options start at byte 20 (after the base 20-byte header)
    paddedOptions.copy(header, 20);

    // STEP 7: Create Temprory TCP segment
    // Concatenate header and data payload
    // Used for checksum calculation
    let tcpSegmentTemp = Buffer.concat([header, data]);

    // STEP 8: Calculate and insert checksum
    // TCP checksum covers: pseudo-header + TCP header + TCP data
    // Pseudo-header includes: src IP, dest IP, protocol (6), TCP length
    let checksum = tcpCheckSum(srcIp, destIp, tcpSegmentTemp);
    // CRITICAL: Checksum goes at offset 16, NOT 20 (20 is where options start)
    header.writeUInt16BE(checksum, 16);

    // STEP 8: Create complete TCP segment
    let tcpSegment = Buffer.concat([header, data]);

    // Return the complete TCP packet
    return tcpSegment;
}

function Decode(packet, skipIPHeader = false) {
    let output = {};

    // If packet includes IP header, skip first 20 bytes
    let tcpStart = skipIPHeader ? 20 : 0;

    // Bytes 0-1: Source Port
    output.sourcePort = packet.readUInt16BE(tcpStart + 0);

    // Bytes 2-3: Destination Port
    output.destinationPort = packet.readUInt16BE(tcpStart + 2);

    // Bytes 4-7: Sequence Number
    output.sequenceNumber = packet.readUInt32BE(tcpStart + 4);

    // Bytes 8-11: Acknowledgment Number
    output.acknowledgmentNumber = packet.readUInt32BE(tcpStart + 8);

    // Byte 12: Data Offset (upper 4 bits) + Reserved (lower 4 bits)
    const dataOffsetAndReserved = packet.readUInt8(tcpStart + 12);
    output.dataOffset = (dataOffsetAndReserved >> 4) & 0x0F; // In 32-bit words

    // Byte 13: Flags
    output.flags = processFlags(packet.readUInt8(tcpStart + 13));

    // Bytes 14-15: Window Size
    output.windowSize = packet.readUInt16BE(tcpStart + 14);

    // Bytes 16-17: Checksum
    output.checksum = packet.readUInt16BE(tcpStart + 16);

    // Bytes 18-19: Urgent Pointer
    output.urgentPointer = packet.readUInt16BE(tcpStart + 18);

    // Calculate header length in bytes (dataOffset is in 32-bit words)
    const headerLength = output.dataOffset * 4;

    // Options exist if header length > 20 bytes (minimum TCP header)
    if (headerLength > 20) {
        const optionsLength = headerLength - 20;
        const optionsBuffer = packet.slice(tcpStart + 20, tcpStart + 20 + optionsLength);
        output.options = processOptions(optionsBuffer);
    } else {
        output.options = [];
    }

    // Data payload starts after the TCP header
    output.dataPayload = packet.slice(tcpStart + headerLength);

    return output;
}

function processFlags(flagBits) {
    let bits = flagBits.toString(2).padStart(8, '0');
    let flags = ['CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN'];
    return flags.filter((flag, index) => bits[index] === '1');
}

function processOptions(optionsArray) {
    const options = [];
    let i = 0;

    const optionTypes = {
        0: 'EOL',           // End of Option List
        1: 'NOP',           // No Operation
        2: 'MSS',           // Maximum Segment Size
        3: 'WS',            // Window Scale
        4: 'SACK-Permitted', // SACK Permitted
        5: 'SACK',          // SACK
        8: 'Timestamps',    // Timestamps
        14: 'AltChkSum',    // Alternate Checksum Request
        15: 'AltChkSumData' // Alternate Checksum Data
    };

    while (i < optionsArray.length) {
        const kind = optionsArray[i];

        // EOL - End of options
        if (kind === 0) {
            options.push({ type: 'EOL', kind: 0 });
            break;
        }

        // NOP - No operation (padding)
        if (kind === 1) {
            options.push({ type: 'NOP', kind: 1 });
            i++;
            continue;
        }

        // All other options have length field
        if (i + 1 < optionsArray.length) {
            const length = optionsArray[i + 1];
            const data = optionsArray.slice(i + 2, i + length);

            options.push({
                type: optionTypes[kind] || `Unknown-${kind}`,
                kind: kind,
                length: length,
                data: data
            });

            i += length;
        } else {
            break;
        }
    }

    return options;
}

// Example usage:
// const opts = [2, 4, 5, 180, 1, 3, 3, 7, 0]; // MSS, NOP, Window Scale, EOL
// console.log(processOptions(opts));

/*
 * IMPORTANT NOTES:
 * 
 * 1. Buffer Allocation: Always use paddedOptions.length when allocating the header
 *    buffer, as the actual header size includes padding.
 * 
 * 2. Data Offset Calculation: Must use paddedOptions.length, not options.length,
 *    because the receiver needs to know the actual header length including padding.
 * 
 * 3. Checksum Position: TCP checksum field is at bytes 16-17, not at byte 20.
 *    Byte 20 is where TCP options begin.
 * 
 * 4. Byte Order: All multi-byte fields use network byte order (big-endian).
 * 
 * 5. Options Padding: TCP options must be padded with zeros to make the total
 *    header length a multiple of 4 bytes (32 bits).
 * 
 * 6. Checksum Calculation: The checksum must be calculated over the entire
 *    TCP segment (header + data) plus a pseudo-header containing IP addresses.
 * 
 * 7. Return Value: Function returns the complete TCP segment (header + data),
 *    ready for transmission or further processing.
 */


module.exports = { Encode, Decode }
