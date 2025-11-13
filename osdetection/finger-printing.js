const {
    guessTTL,
    getSequenceBehavior,
    getAckBehavior,
    getTCPFlags
} = require('./util');

/**
 * TCP Option Kind Constants
 * Reference: RFC 793, RFC 1323, RFC 2018
 */
const TCP_OPTION_KINDS = {
    EOL: 0,              // End of Option List
    NOP: 1,              // No Operation
    MSS: 2,              // Maximum Segment Size
    WINDOW_SCALE: 3,     // Window Scale
    SACK_PERMITTED: 4,   // SACK Permitted
    SACK: 5,             // Selective Acknowledgment
    TIMESTAMP: 8         // Timestamps
};

/**
 * Nmap Option Codes
 * Single character codes used in Nmap fingerprints
 */
const NMAP_OPTION_CODES = {
    EOL: 'L',
    NOP: 'N',
    MSS: 'M',
    WINDOW_SCALE: 'W',
    SACK_PERMITTED: 'S',
    SACK: 'K',
    TIMESTAMP: 'T',
    UNKNOWN: 'U'
};

/**
 * Converts a single TCP option to Nmap format
 * 
 * @param {Object} option - TCP option object with kind and data
 * @returns {string} Nmap-formatted option string
 */
function convertSingleOption(option) {
    switch (option.kind) {
        case TCP_OPTION_KINDS.EOL:
            return NMAP_OPTION_CODES.EOL;

        case TCP_OPTION_KINDS.NOP:
            return NMAP_OPTION_CODES.NOP;

        case TCP_OPTION_KINDS.MSS:
            return formatMSSOption(option.data);

        case TCP_OPTION_KINDS.WINDOW_SCALE:
            return formatWindowScaleOption(option.data);

        case TCP_OPTION_KINDS.SACK_PERMITTED:
            return NMAP_OPTION_CODES.SACK_PERMITTED;

        case TCP_OPTION_KINDS.SACK:
            return NMAP_OPTION_CODES.SACK;

        case TCP_OPTION_KINDS.TIMESTAMP:
            return formatTimestampOption(option.data);

        default:
            return formatUnknownOption(option.kind);
    }
}

/**
 * Format MSS (Maximum Segment Size) option
 * 
 * @param {Buffer} data - Option data buffer
 * @returns {string} Formatted MSS option (e.g., "M5B4")
 */
function formatMSSOption(data) {
    if (!data || data.length < 2) {
        return NMAP_OPTION_CODES.MSS;
    }

    const mss = data.readUInt16BE(0);
    const hexValue = mss.toString(16).toUpperCase().replace(/^0+/, '') || '0';
    return NMAP_OPTION_CODES.MSS + hexValue;
}

/**
 * Format Window Scale option
 * 
 * @param {Buffer} data - Option data buffer
 * @returns {string} Formatted Window Scale option (e.g., "WA")
 */
function formatWindowScaleOption(data) {
    if (!data || data.length < 1) {
        return NMAP_OPTION_CODES.WINDOW_SCALE;
    }

    const scale = data.readUInt8(0);
    const hexValue = scale.toString(16).toUpperCase();
    return NMAP_OPTION_CODES.WINDOW_SCALE + hexValue;
}

/**
 * Format Timestamp option
 * 
 * Nmap uses two binary digits after T:
 * - First digit: 0 if TSval is zero, 1 if non-zero
 * - Second digit: 0 if TSecr is zero, 1 if non-zero
 * 
 * @param {Buffer} data - Option data buffer (8 bytes)
 * @returns {string} Formatted Timestamp option (e.g., "T11")
 */
function formatTimestampOption(data) {
    if (!data || data.length < 8) {
        return NMAP_OPTION_CODES.TIMESTAMP;
    }

    const tsval = data.readUInt32BE(0);  // Timestamp Value
    const tsecr = data.readUInt32BE(4);  // Timestamp Echo Reply

    const tsvalDigit = tsval === 0 ? '0' : '1';
    const tsecrDigit = tsecr === 0 ? '0' : '1';

    return NMAP_OPTION_CODES.TIMESTAMP + tsvalDigit + tsecrDigit;
}

/**
 * Format unknown TCP option
 * 
 * @param {number} kind - Option kind number
 * @returns {string} Formatted unknown option (e.g., "U1F")
 */
function formatUnknownOption(kind) {
    const hexKind = kind.toString(16).toUpperCase();
    return NMAP_OPTION_CODES.UNKNOWN + hexKind;
}

/**
 * Converts TCP options array to Nmap OPS format
 * 
 * CRITICAL: Preserves the EXACT order of TCP options as they appear in the packet,
 * including every NOP. Do NOT reorder options!
 * 
 * @param {Array} options - Array of TCP option objects
 * @returns {string} Nmap-formatted options string (e.g., "M5B4ST11NW3")
 */
function convertToNmapOPS(options) {
    if (!options || options.length === 0) {
        return '';
    }

    return options.map(option => convertSingleOption(option)).join('');
}

/**
 * Converts multiple TCP packets' options to Nmap OPS fingerprint format
 * 
 * This matches the OPS(O1=...%O2=...%O3=...) structure used in Nmap fingerprints
 * 
 * @param {Array} packets - Array of decoded TCP packets (typically T1-T6 responses)
 * @returns {string} Complete OPS fingerprint string
 * 
 * @example
 * // Returns: "OPS(O1=M5B4ST11NW3%O2=M5B4ST11NW3%O3=M5B4T11NW3%O4=M5B4ST11NW3%O5=M5B4ST11NW3%O6=M5B4ST11)"
 */
function convertToNmapOPSFingerprint(packets) {
    if (!packets || packets.length === 0) {
        return 'OPS()';
    }

    const opsValues = packets.map((packet, index) => {
        const opsString = convertToNmapOPS(packet.options);
        return `O${index + 1}=${opsString}`;
    });

    return `OPS(${opsValues.join('%')})`;
}

/**
 * Extract TCP window sizes from packets and format as WIN fingerprint
 * 
 * @param {Array} packets - Array of decoded TCP packets
 * @returns {string} WIN fingerprint string (e.g., "WIN(W1=8000%W2=8000%W3=8000)")
 * 
 * @example
 * // Returns: "WIN(W1=8000%W2=8000%W3=8000%W4=8000%W5=8000%W6=8000)"
 */
function extractWindowFingerprint(packets) {
    if (!packets || packets.length === 0) {
        return 'WIN()';
    }

    const windowValues = [];

    for (let i = 0; i < packets.length; i++) {
        const packet = packets[i];

        if (!packet || packet.windowSize === undefined || packet.windowSize === null) {
            continue;
        }

        const hexValue = packet.windowSize.toString(16).toUpperCase();
        windowValues.push(`W${i + 1}=${hexValue}`);
    }

    return `WIN(${windowValues.join('%')})`;
}

/**
 * Format TTL value with range for Nmap fingerprint
 * 
 * @param {number} ttl - Time To Live value
 * @returns {string} Formatted TTL range (e.g., "3C-46")
 */
function formatTTL(ttl) {
    const ttlHex = ttl.toString(16).toUpperCase();
    const ttlPlus10 = (ttl + 10).toString(16).toUpperCase();
    return `${ttlHex}-${ttlPlus10}`;
}

/**
 * Format window size to hex
 * 
 * @param {number} windowSize - TCP window size
 * @returns {string} Hex-formatted window size
 */
function formatWindowSize(windowSize) {
    if (windowSize === undefined || windowSize === null) {
        return '0';
    }
    return windowSize.toString(16).toUpperCase();
}

/**
 * Build a complete Nmap Tn test result
 * 
 * Constructs a fingerprint string for a single TCP test (T1-T7, IE, etc.)
 * following Nmap's exact format and field ordering.
 * 
 * @param {Object} tcpPacket - Decoded TCP packet object
 * @param {Object} ipPacket - Decoded IP packet object
 * @param {string} testName - Test identifier (e.g., "T1", "T2", "IE")
 * @param {number} ourSeqNumber - Our original sequence number (default: 0)
 * @returns {string} Complete Tn fingerprint string
 * 
 * @example
 * // Returns: "T1(R=Y%DF=Y%T=3C-46%TG=40%W=8000%S=A%A=S+%F=AS%O=M5B4ST11NW3%RD=0%Q=)"
 */
function buildTn(tcpPacket, ipPacket, testName, ourSeqNumber = 0) {
    // No response received
    if (!tcpPacket || !ipPacket) {
        return `${testName}(R=N)`;
    }

    const fields = {
        R: 'Y',                                                          // Response received
        DF: ipPacket.flags?.DF ? 'Y' : 'N',                            // Don't Fragment flag
        T: formatTTL(ipPacket.ttl),                                     // TTL with range
        TG: guessTTL(ipPacket.ttl),                                     // Initial TTL guess
        W: formatWindowSize(tcpPacket.windowSize),                      // Window size (hex)
        S: getSequenceBehavior(tcpPacket.sequenceNumber, ourSeqNumber), // Sequence behavior
        A: getAckBehavior(tcpPacket.acknowledgmentNumber, ourSeqNumber),// ACK behavior
        F: getTCPFlags(tcpPacket.flags),                                // TCP flags
        O: convertToNmapOPS(tcpPacket.options || []),                  // TCP options
        RD: tcpPacket.dataPayload?.length || 0,                         // Response data length
        Q: ''                                                            // Quirks (reserved)
    };

    // Build fingerprint in Nmap's exact field order
    const fingerprint = Object.entries(fields)
        .map(([key, value]) => `${key}=${value}`)
        .join('%');

    return `${testName}(${fingerprint})`;
}

/**
 * Validate packet structure before processing
 * 
 * @param {Object} packet - Packet object to validate
 * @returns {boolean} True if packet is valid
 */
function isValidPacket(packet) {
    return packet &&
        typeof packet === 'object' &&
        (packet.windowSize !== undefined || packet.options !== undefined);
}

/**
 * Build fingerprint for multiple test responses
 * 
 * @param {Array} packets - Array of packet objects with tcp and ip data
 * @param {string} testPrefix - Test name prefix (e.g., "T", "IE")
 * @param {number} ourSeqNumber - Our original sequence number
 * @returns {Array} Array of fingerprint strings
 */
function buildMultipleTn(packets, testPrefix = 'T', ourSeqNumber = 0) {
    return packets.map((packet, index) => {
        const testName = `${testPrefix}${index + 1}`;
        return buildTn(packet.tcp, packet.ip, testName, ourSeqNumber);
    });
}

module.exports = {
    // Main exports
    buildTn,
    convertToNmapOPS,
    convertToNmapOPSFingerprint,
    extractWindowFingerprint,
    buildMultipleTn,

    // Utility exports for advanced usage
    formatTTL,
    formatWindowSize,
    isValidPacket,

    // Constants exports
    TCP_OPTION_KINDS,
    NMAP_OPTION_CODES
};