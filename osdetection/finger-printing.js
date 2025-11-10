const { guessTTL, getSequenceBehavior, getAckBehavior, getTCPFlags } = require('./util');


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

    // console.log('option', option)

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


/* 
 *Collect TCP window sizes from all packets and encode them as WIN(...) fingerprint values
*/
function extractWindowFingerprint(packets) {
    let windowValues = [];
    let index = 0;
    for (packet of packets) {
        if (!packet.windowSize) {
            continue;
        }
        const hexValue = packet.windowSize.toString(16).toUpperCase();
        windowValues.push(`W${index + 1}=${hexValue}`);
        index++;
    }


    return `WIN(${windowValues.join('%')})`;
}

function buildTn(tcpPacket, ipPacket, testName, ourSeqNumber = 0) {
    // No response received
    if (!tcpPacket || !ipPacket) {
        return `${testName}(R=N)`;
    }

    // R - Response received
    const r = 'Y';

    // DF - Don't Fragment flag
    const df = ipPacket.flags?.DF ? 'Y' : 'N';

    // T - TTL in hex
    const ttl = ipPacket.ttl
        ? ipPacket.ttl.toString(16).toUpperCase()
        : '';

    // TG - TTL Guess (initial TTL before hops)
    const tg = guessTTL(ipPacket.ttl);

    // S - Sequence number behavior
    const s = getSequenceBehavior(tcpPacket.sequenceNumber);

    // A - Acknowledgment number behavior
    const a = getAckBehavior(tcpPacket.acknowledgmentNumber, ourSeqNumber);

    // F - TCP flags
    const f = getTCPFlags(tcpPacket.flags);

    // RD - Response Data (payload length)
    const rd = tcpPacket.dataPayload?.length || 0;

    // Q - Quirks (for now empty, needs analysis)
    const q = '';

    // O - TCP Options
    const o = convertToNmapOPS(tcpPacket.options || []);

    // W - Window size in hex
    const w = tcpPacket.windowSize
        ? tcpPacket.windowSize.toString(16).toUpperCase()
        : '0';

    // Build in correct Nmap order
    return `${testName}(R=${r}%DF=${df}%T=${ttl}%TG=${tg}%S=${s}%A=${a}%F=${f}%RD=${rd}%Q=${q}%O=${o}%W=${w})`;
}



module.exports = { buildTn, convertToNmapOPSFingerprint, extractWindowFingerprint }