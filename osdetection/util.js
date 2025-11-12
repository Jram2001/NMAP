/**
 * Guess the initial TTL based on received TTL
 * Common initial values: 32, 64, 128, 255
 */
function guessTTL(receivedTTL) {
    if (!receivedTTL) return '';

    if (receivedTTL <= 32) return '20';      // 32
    if (receivedTTL <= 64) return '40';      // 64
    if (receivedTTL <= 128) return '80';     // 128
    if (receivedTTL <= 255) return 'FF';     // 255

    return receivedTTL.toString(16).toUpperCase();
}

/**
 * Determine sequence number behavior
 * Z = Zero
 * A = Same as ACK we sent
 * A+ = ACK + 1
 * O = Other (non-zero)
 */
function getSequenceBehavior(seqNumber, ourSeqNumber) {
    switch (seqNumber) {
        case 0:
            return 'Z';
        case seqNumber == ourSeqNumber:
            return 'A';
        case ourSeqNumber == seqNumber + 1:
            return 'A+';
        default:
            return 0;
    }
    // if (seqNumber === 0) return 'Z';
    // return 'O';  // Other (non-zero)
}

/**
 * Determine ACK number behavior
 * Z = Zero
 * S = Same as our SEQ
 * S+ = Our SEQ + 1 (correct TCP behavior)
 * O = Other
 */
function getAckBehavior(ackNumber, ourSeqNumber) {
    if (ackNumber === 0) return 'Z';
    if (ackNumber === ourSeqNumber) return 'S';
    if (ackNumber === ourSeqNumber + 1) return 'S+';
    return 'O';
}

/**
 * Convert TCP flags array to Nmap short form
 * S=SYN, A=ACK, R=RST, F=FIN, P=PSH, U=URG, E=ECE, C=CWR
 */
function getTCPFlags(flagsArray) {
    if (!flagsArray || flagsArray.length === 0) return '';

    const map = {
        'SYN': 'S',
        'ACK': 'A',
        'RST': 'R',
        'FIN': 'F',
        'PSH': 'P',
        'URG': 'U',
        'ECE': 'E',
        'CWR': 'C'
    };

    // Nmap orders flags: A, S, R, F, P, U, E, C
    const order = ['ACK', 'SYN', 'RST', 'FIN', 'PSH', 'URG', 'ECE', 'CWR'];

    return order
        .filter(flag => flagsArray.includes(flag))
        .map(flag => map[flag])
        .join('');
}


module.exports = { guessTTL, getSequenceBehavior, getAckBehavior, getTCPFlags }