const NmapProbeOptions = require("../utils/tcp/tcp-option-probes");

/**
 * Converts TCP options from decoded format to Nmap OPS format
 * 
 * IMPORTANT: Nmap preserves the EXACT order of TCP options as they appear in the packet,
 * including every NOP. Do NOT reorder options!
 * 
 * @param {Array} options - Array of TCP option objects from your decoder
 * @returns {string} Nmap-formatted options string
 */
function convertToNmapOPS(options) {
    if (!options || options.length === 0) {
        return '';
    }

    let result = '';

    console.log('option', option)

    for (const option of options) {
        switch (option.kind) {
            case 0: // End of Option List (EOL)
                result += 'L';
                break;

            case 1: // NOP (No Operation)
                result += 'N';
                break;

            case 2: // MSS (Maximum Segment Size)
                if (option.data && option.data.length >= 2) {
                    const mss = option.data.readUInt16BE(0);
                    result += 'M' + mss.toString(16).toUpperCase().replace(/^0/, '');
                } else {
                    result += 'M';
                }
                break;

            case 3: // Window Scale
                if (option.data && option.data.length >= 1) {
                    const scale = option.data.readUInt8(0);
                    result += 'W' + scale.toString(16).toUpperCase();
                } else {
                    result += 'W';
                }
                break;

            case 4: // SACK Permitted
                result += 'S';
                break;

            case 5: // SACK (Selective Acknowledgment)
                result += 'K';
                break;

            case 8: // Timestamps
                if (option.data && option.data.length >= 8) {
                    const tsval = option.data.readUInt32BE(0);   // First 4 bytes: Timestamp Value
                    const tsecr = option.data.readUInt32BE(4);   // Last 4 bytes: Timestamp Echo Reply

                    // Nmap uses two binary digits after T:
                    // First digit: 0 if TSval is zero, 1 if non-zero
                    // Second digit: 0 if TSecr is zero, 1 if non-zero
                    const tsvalDigit = tsval === 0 ? '0' : '1';
                    const tsecrDigit = tsecr === 0 ? '0' : '1';

                    result += 'T' + tsvalDigit + tsecrDigit;
                } else {
                    result += 'T';
                }
                break;

            default:
                // Unknown option - represent as generic with kind number
                result += 'U' + option.kind.toString(16).toUpperCase();
                break;
        }
    }

    return result;
}

/**
 * Converts multiple TCP packets' options to Nmap OPS format
 * This matches the OPS(O1=...%O2=...%O3=...) structure
 * 
 * @param {Array} packets - Array of decoded TCP packets (T1-T6 responses)
 * @returns {string} Full OPS fingerprint string
 */
function convertToNmapOPSFingerprint(packets) {
    const opsValues = packets.map((packet, index) => {
        const opsString = convertToNmapOPS(packet.options);
        return `O${index + 1}=${opsString}`;
    });

    return `OPS(${opsValues.join('%')})`;
}


//Extract WIN data window size
function extractWindowFingerprint(packets) {
    let windowValues = [];
    let index = 0;
    for (packet of packets) {
        console.log('s', packet)
        if (!packet.windowSize) {
            continue;
        }
        const hexValue = packet.windowSize.toString(16).toUpperCase();
        windowValues.push(`W${index + 1}=${hexValue}`);
        index++;
    }


    return `WIN(${windowValues.join('%')})`;
}

// For your packet:
const packet1 = {
    windowSize: 65535,
};

// If you have all 6 packets:
const packets = [packet1, packet2, packet3, packet4, packet5, packet6];
const winFingerprint = extractWindowFingerprint(packets);
console.log(winFingerprint);
// Output: WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFFF)




module.exports = { convertToNmapOPS, convertToNmapOPSFingerprint }