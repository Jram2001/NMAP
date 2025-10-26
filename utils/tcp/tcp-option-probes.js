/**
 * Nmap TCP OS Detection - Header Options Arrays
 * Simple arrays of TCP options for each probe
 */

const { optEOL, optNOP, optMSS, optWScale, optSACK, optTimestamp, optPadding } = require('./option-bulder');

// T1 Probe - SYN to open port
const T1_options = optPadding(Buffer.concat([
    optWScale(10),
    optNOP(),
    optMSS(1460),
    optTimestamp(0xFFFFFFFF, 0),
    optSACK()
]));

// T2 Probe - SYN with unusual options to open port
const T2_options = optPadding(Buffer.concat([
    optMSS(265),
    optSACK(),
    optTimestamp(0xFFFFFFFF, 0),
    optNOP(),
    optWScale(15)
]));

// T3 Probe - SYN to closed port
const T3_options = optPadding(Buffer.concat([
    optWScale(10),
    optNOP(),
    optMSS(1400),
    optTimestamp(0xFFFFFFFF, 0),
    optSACK()
]));

// T4 Probe - ACK to open port
const T4_options = optPadding(Buffer.concat([
    optTimestamp(0xFFFFFFFF, 0)
]));

// T5 Probe - SYN to closed port (no options)
const T5_options = Buffer.alloc(0);

// T6 Probe - ACK to closed port (no options)
const T6_options = Buffer.alloc(0);

// T7 Probe - FIN/PSH/URG to closed port (no options)
const T7_options = Buffer.alloc(0);

// ECN Probe - SYN with ECE+CWR flags
const ECN_options = optPadding(Buffer.concat([
    optWScale(10),
    optNOP(),
    optMSS(1460),
    optSACK(),
    optNOP(),
    optNOP()
]));

// Additional probes with different option combinations

// Probe with MSS only
const MSS_only = optPadding(Buffer.concat([
    optMSS(1460)
]));

// Probe with WScale only
const WSCALE_only = optPadding(Buffer.concat([
    optWScale(7)
]));

// Probe with SACK only
const SACK_only = optPadding(Buffer.concat([
    optSACK()
]));

// Probe with timestamp only
const TIMESTAMP_only = optPadding(Buffer.concat([
    optTimestamp()
]));

// Probe with all options (different order)
const ALL_options_v1 = optPadding(Buffer.concat([
    optMSS(1460),
    optWScale(7),
    optSACK(),
    optTimestamp()
]));

// Probe with all options (reverse order)
const ALL_options_v2 = optPadding(Buffer.concat([
    optTimestamp(),
    optSACK(),
    optWScale(7),
    optMSS(1460)
]));

// Probe with unusual MSS values
const UNUSUAL_MSS_1 = optPadding(Buffer.concat([
    optMSS(536),    // Minimum MSS
    optSACK()
]));

const UNUSUAL_MSS_2 = optPadding(Buffer.concat([
    optMSS(65535),  // Maximum MSS
    optWScale(0)
]));

// Probe with unusual window scale values
const UNUSUAL_WSCALE_1 = optPadding(Buffer.concat([
    optWScale(0),   // No scaling
    optMSS(1460)
]));

const UNUSUAL_WSCALE_2 = optPadding(Buffer.concat([
    optWScale(14),  // Maximum valid scale
    optSACK()
]));

const INVALID_WSCALE = optPadding(Buffer.concat([
    optWScale(16),  // Invalid scale (> 14)
    optMSS(1200)
]));

// Probes with different timestamp values
const TIMESTAMP_zero = optPadding(Buffer.concat([
    optTimestamp(0, 0),
    optMSS(1460)
]));

const TIMESTAMP_small = optPadding(Buffer.concat([
    optTimestamp(1, 0),
    optSACK()
]));

// Probe with maximum options (40 bytes total)
const MAX_options = Buffer.concat([
    optMSS(1460),               // 4 bytes
    optWScale(7),               // 3 bytes
    optSACK(),                  // 2 bytes
    optTimestamp(0xFFFFFFFF, 0), // 10 bytes
    Buffer.alloc(21, 0x01)      // 21 NOP bytes = 40 total
]);

// Probe with minimal options
const MIN_options = optPadding(Buffer.concat([
    optNOP()
]));

// Probes for specific OS detection
const LINUX_probe = optPadding(Buffer.concat([
    optMSS(1460),
    optSACK(),
    optTimestamp(),
    optNOP(),
    optWScale(7)
]));

const WINDOWS_probe = optPadding(Buffer.concat([
    optMSS(1460),
    optNOP(),
    optWScale(8),
    optNOP(),
    optNOP(),
    optSACK()
]));

const BSD_probe = optPadding(Buffer.concat([
    optMSS(1460),
    optNOP(),
    optWScale(6),
    optSACK(),
    optTimestamp()
]));

// Export all option arrays
module.exports = {
    // Core Nmap probes
    T1_options,
    T2_options,
    T3_options,
    T4_options,
    T5_options,
    T6_options,
    T7_options,
    ECN_options,

    // Single option probes
    MSS_only,
    WSCALE_only,
    SACK_only,
    TIMESTAMP_only,

    // Combination probes
    ALL_options_v1,
    ALL_options_v2,

    // Unusual value probes
    UNUSUAL_MSS_1,
    UNUSUAL_MSS_2,
    UNUSUAL_WSCALE_1,
    UNUSUAL_WSCALE_2,
    INVALID_WSCALE,

    // Timestamp variants
    TIMESTAMP_zero,
    TIMESTAMP_small,

    // Size variants
    MAX_options,
    MIN_options,

    // OS-specific probes
    LINUX_probe,
    WINDOWS_probe,
    BSD_probe
};