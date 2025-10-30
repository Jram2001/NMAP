/**
 * =====================================================================
 * TCP/IP OS Fingerprinting - Response Pattern Database
 * =====================================================================
 * This object maps known operating systems to their expected TCP option
 * response patterns (O1-O6) when subjected to the standard 6 Nmap
 * SEQ probes. It also includes auxiliary data like TTL and typical
 * window sizes for more accurate fingerprinting.
 *
 * How to use:
 * 1. Send probes P1 through P6 to a target.
 * 2. Capture the SYN-ACK responses for each probe.
 * 3. Parse the TCP options to get six strings: O1, O2, O3, O4, O5, O6.
 * 4. Iterate through this responsePatterns object.
 * 5. Compare your captured O1-O6 values against the `o_pattern` for
 *    each OS.
 * 6. The OS with the highest number of matches is the likely candidate.
 *
 * KEY DISCRIMINATOR: The O2 value is critical. Windows strips the
 * WSCALE(0) option, while Linux/BSD do not.
 */
const responsePatterns = {
    "Linux (Modern Kernel 4.x-6.x)": {
        description: "Modern Linux distributions (Ubuntu, Debian, CentOS, etc.) and Android. Known for robust TCP/IP implementation and echoing most options.",
        likelyOS: ["Linux", "Android"],
        confidence: 85,
        auxiliary: {
            ttl: 64,
            window_size: "Varies, often > 29200"
        },
        o_pattern: {
            O1: ["MNNTS", "MNNTSW"],
            O2: ["MWST", "MWSTE"],
            O3: ["TNNWM", "MNNTSW"],
            O4: ["STW", "STWE", "MSTW"],
            O5: ["MSTW", "MSTWE"],
            O6: ["MST"]
        },
        notes: "Key differentiator is preserving WSCALE(0) in O2. Tends to have the most complete option echo. TTL is almost always 64."
    },

    "Windows (10/11/Server 2016-2025)": {
        description: "Modern Windows desktop and server operating systems. The most reliable fingerprint is its handling of the WSCALE(0) option.",
        likelyOS: ["Windows"],
        confidence: 90,
        auxiliary: {
            ttl: 128,
            window_size: "64240, 65535, or 8192"
        },
        o_pattern: {
            O1: ["MNNTS", "MNTS"],
            O2: ["MST", "MSTE"],
            O3: ["TNNWM", "MNNWTS"],
            O4: ["STW", "STWE", "MSTW"],
            O5: ["MSTW", "MSTWE"],
            O6: ["MST", "MS"]
        },
        notes: "The O2 response lacking 'W' is the strongest signal for Windows. TTL is almost always 128."
    },

    "FreeBSD / OpenBSD": {
        description: "Berkeley Software Distribution family, including FreeBSD, OpenBSD, and derivatives like pfSense. Also very similar to macOS.",
        likelyOS: ["FreeBSD", "OpenBSD", "NetBSD", "macOS"],
        confidence: 75,
        auxiliary: {
            ttl: 64,
            window_size: "Varies, often > 65000"
        },
        o_pattern: {
            O1: ["MNNTS", "MTS"],
            O2: ["MWST", "MWSTE"],
            O3: ["TNNWM", "TSNNWM"],
            O4: ["STW", "STWE"],
            O5: ["MSTW", "MSTWE"],
            O6: ["MST"]
        },
        notes: "Similar to Linux but may show stronger adherence to SACKOK-first or TS-first ordering in O3/O4 responses. TTL is typically 64."
    },

    "macOS (Monterey, Ventura, Sonoma)": {
        description: "Modern Apple desktop operating systems. Based on BSD but with its own specific TCP/IP stack nuances.",
        likelyOS: ["macOS"],
        confidence: 80,
        auxiliary: {
            ttl: 64,
            window_size: "Often 65535"
        },
        o_pattern: {
            O1: ["MNWST", "MNNWST"],
            O2: ["MWST", "MWSTE"],
            O3: ["TNNWM", "MNWTS"],
            O4: ["STW", "STWE"],
            O5: ["MSTW", "MSTWE"],
            O6: ["MST"]
        },
        notes: "Behaves very similarly to FreeBSD. The best way to distinguish is often through the timestamp increment rate, which is more regular on macOS."
    },

    "Cisco IOS / Network Gear": {
        description: "Routers, switches, and firewalls running operating systems like Cisco IOS. Often have customized, sometimes limited, TCP stacks.",
        likelyOS: ["Cisco IOS", "Juniper Junos", "FortiOS"],
        confidence: 60,
        auxiliary: {
            ttl: 255,
            window_size: "Often small, e.g., 4128, 16384"
        },
        o_pattern: {
            O1: ["MTS", "MNTS"],
            O2: ["MST", "MSTE"],
            O3: ["M"],
            O4: ["M", ""],
            O5: ["MST", "MS"],
            O6: ["MST", "M"]
        },
        notes: "High TTL (often 255) is a strong indicator. May not respond to all probes or may provide very minimal option sets. Fingerprints can vary widely by firmware version."
    },

    "Embedded / IoT (BusyBox/Linux)": {
        description: "Lightweight devices like cameras, printers, and smart home gadgets, often running a stripped-down Linux kernel with BusyBox.",
        likelyOS: ["Embedded Linux", "IoT Device"],
        confidence: 50,
        auxiliary: {
            ttl: 64,
            window_size: "Varies, often small or non-standard"
        },
        o_pattern: {
            O1: ["MTS", "MS"],
            O2: ["MST", "MS"],
            O3: ["TM", "TWM", "M"],
            O4: ["ST", "S", ""],
            O5: ["MST", "MS"],
            O6: ["M", "MS", "MST"]
        },
        notes: "Highly ambiguous due to wide variation. Often lacks WSCALE or full SACK support. Responses can be minimal or incomplete. Look for non-standard window sizes."
    }
};

module.exports = { responsePatterns };


const olayoutSignatures = [
    {
        id: "sig-1",
        olayout: ["MSS", "NOP", "NOP", "TS"],
        name: "MSS → NOP → NOP → TS",
        description: "Dominant signature for modern Linux kernels (3.x–6.x), Android (Post-2018, esp. Qualcomm/Mediatek) and many embedded distributions. NOPs used for TS padding; middlebox modification possible.",
        likelyOS: ["Linux kernel 3.x–6.x", "Android 9+", "Embedded Linux (IoT)"],
        confidence: 80,
        notes: "Canonical in nmap-os-db and p0f.fp (Linux, Android) [38][40][30]. Confirm with window size, TTL, and timestamp value for enhanced precision."
    },
    {
        id: "sig-2",
        olayout: ["WSCALE", "NOP", "MSS", "SACKOK", "NOP", "NOP"],
        name: "WSCALE → NOP → MSS → SACKOK → NOP → NOP",
        description: "Characteristic of Windows NT/Server 2012–2025, plus Microsoft cloud VMs and some firmware-modified stacks. WSCALE first; NOPs for alignment.",
        likelyOS: ["Windows NT/10/11", "Windows Server", "Firmware (routers)"],
        confidence: 70,
        notes: "Latest Windows desktop/server, can also appear with middlebox-modified cloud VM stacks [38][22]. Window size and TTL=128 further corroborate ID."
    },
    {
        id: "sig-3",
        olayout: ["MSS", "SACKOK", "TS", "NOP"],
        name: "MSS → SACKOK → TS → NOP",
        description: "Typical of BSD (FreeBSD, OpenBSD, NetBSD), and macOS Ventura+, plus legacy Unix. SACKOK precedes TS.",
        likelyOS: ["FreeBSD", "OpenBSD", "macOS", "NetBSD", "Unix"],
        confidence: 65,
        notes: "Distinctive among BSDs, but recent macOS releases show similar layouts. Compare with option values and quirks for exact flavor."
    },
    {
        id: "sig-4",
        olayout: ["MSS", "WSCALE", "SACKOK", "TS"],
        name: "MSS → WSCALE → SACKOK → TS",
        description: "Permutational full-option layout for modern Linux 5/6.x, BSD variants, and high-end network gear.",
        likelyOS: ["Linux 5.x–6.x", "Modern BSDs", "Network hardware (2020+)"],
        confidence: 60,
        notes: "Presence of all four main options is more diagnostic than ordering. Device-specific, aligns with nmap-os-db and p0f signatures."
    },
    {
        id: "sig-5",
        olayout: ["MSS", "TS"],
        name: "MSS → TS",
        description: "Minimal options; found on stripped embedded stacks, IoT sensors, legacy Unix, and some hypervisor VMs.",
        likelyOS: ["IoT devices", "Legacy Unix", "Custom firmware"],
        confidence: 50,
        notes: "Highly ambiguous; combine with window size, TTL, and network context for practical identification."
    },
    {
        id: "sig-6",
        olayout: ["WSCALE", "MSS", "SACKOK", "TS", "NOP"],
        name: "WSCALE → MSS → SACKOK → TS → NOP",
        description: "Alternative ordering when middleboxes or certain routers intervene; can occur in Windows, router firmware, and network gear.",
        likelyOS: ["Windows", "Routers", "Middlebox-altered stacks"],
        confidence: 45,
        notes: "Check for anomalies like reordered or stripped options, which may result from network proxies or transparent NAT."
    },
    {
        id: "sig-7",
        olayout: ["MSS", "NOP", "SACKOK", "TS", "NOP"],
        name: "MSS → NOP → SACKOK → TS → NOP",
        description: "Seen across Linux, BSD, and certain embedded platforms; NOP padding between options common in kernel 4.x+.",
        likelyOS: ["Linux", "BSD", "Embedded"],
        confidence: 55,
        notes: "Multiple vendors use this; treat as a supplemental heuristic in fingerprinting, confirm with additional metrics."
    },
    {
        id: "sig-8",
        olayout: ["MSS", "SACKOK", "TS", "NOP", "WSCALE"],
        name: "MSS → SACKOK → TS → NOP → WSCALE",
        description: "Common in Android, Linux-based mobile devices, and recent embedded distributions. WSCALE last after NOP.",
        likelyOS: ["Android 10+", "Linux (Mobile)", "Embedded"],
        confidence: 85,
        notes: "High confidence for Android/Qualcomm/Mediatek. NOP before WSCALE is a unique pattern for mobile stacks."
    }
];

const ttlSignatures = [
    {
        id: "ttl-1",
        ttlRange: [60, 64],
        name: "Initial TTL ≈ 64",
        description: "Typical of Linux, Android, macOS, and BSD-like systems.",
        likelyOS: ["Linux", "Android", "macOS", "BSD", "Unix-like"],
        confidence: 80,
        notes: "Most Linux and Unix-derived OSes start at 64; observed value depends on hop count."
    },
    {
        id: "ttl-2",
        ttlRange: [120, 128],
        name: "Initial TTL ≈ 128",
        description: "Typical of Windows operating systems.",
        likelyOS: ["Windows", "Windows Server"],
        confidence: 85,
        notes: "Windows stacks consistently use 128 as the initial TTL; middleboxes rarely alter this."
    },
    {
        id: "ttl-3",
        ttlRange: [240, 255],
        name: "Initial TTL ≈ 255",
        description: "Typical of Cisco routers, network appliances, and some embedded devices.",
        likelyOS: ["Cisco IOS", "Network equipment", "Embedded routers"],
        confidence: 75,
        notes: "High TTLs are rare in desktop OSes — usually routers or firewalls."
    },
    {
        id: "ttl-4",
        ttlRange: [30, 32],
        name: "Initial TTL ≈ 32",
        description: "Seen on some older embedded stacks or special-purpose systems.",
        likelyOS: ["Legacy embedded devices", "Old Unix variants"],
        confidence: 40,
        notes: "Low TTL defaults were used in very early stacks; rare in modern systems."
    },
    {
        id: "ttl-5",
        ttlRange: [100, 112],
        name: "Initial TTL ≈ 112",
        description: "Sometimes used by Solaris and certain custom networking stacks.",
        likelyOS: ["Solaris", "Proprietary network OS"],
        confidence: 55,
        notes: "Not common today; occasionally seen on legacy enterprise systems."
    },
    {
        id: "ttl-6",
        ttlRange: [190, 200],
        name: "Initial TTL ≈ 196",
        description: "Observed in specific router firmwares or modified TCP/IP stacks.",
        likelyOS: ["Custom firmware", "RouterOS", "OpenWRT (custom builds)"],
        confidence: 45,
        notes: "Intermediate TTL defaults sometimes indicate tweaked or nonstandard kernels."
    },
    {
        id: "ttl-7",
        ttlRange: [50, 58],
        name: "TTL slightly below 64 (after hops)",
        description: "Likely a Linux/Unix system a few hops away.",
        likelyOS: ["Linux", "Unix-like"],
        confidence: 70,
        notes: "Subtract hop count to infer initial TTL; typical of remote Linux hosts."
    }
];


function extractOptions(options) {
    if (!options || !Array.isArray(options)) {
        throw new Error("Invalid options: 'options' must be an array.");
    }

    return options.map(option => option.type);
}


// === normalizer: map variants to canonical tokens ===
const TOKEN_MAP = {
    'timestamps': 'TS',
    'ts': 'TS',
    'mss': 'MSS',
    'nop': 'NOP',
    'sackok': 'SACKOK',
    'sack-permitted': 'SACKOK',
    'wscale': 'WSCALE',
    'window-scale': 'WSCALE'
};

function normalize(token) {
    if (!token && token !== 0) return token;
    const t = String(token).trim().toLowerCase();
    return TOKEN_MAP[t] ?? token.toUpperCase();
}

// === LCS (longest common subsequence) for sequence similarity ===
function lcsLength(a, b) {
    const n = a.length, m = b.length;
    const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
    for (let i = 1; i <= n; i++) {
        for (let j = 1; j <= m; j++) {
            if (a[i - 1] === b[j - 1]) dp[i][j] = dp[i - 1][j - 1] + 1;
            else dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
        }
    }
    return dp[n][m];
}

// === main matcher for a single signature ===
function matchSignature(observedRaw, signature, opts = {}) {
    // options
    const weights = {
        lcsWeight: opts.lcsWeight ?? 0.6,
        exactPosWeight: opts.exactPosWeight ?? 0.4
    };

    // normalize arrays
    const observed = (observedRaw || []).map(normalize);
    const target = (signature.olayout || []).map(normalize);

    // exact positional matches (count indices where normalized tokens equal)
    let exactMatches = 0;
    const minLen = Math.min(observed.length, target.length);
    for (let i = 0; i < minLen; i++) {
        if (observed[i] === target[i]) exactMatches++;
    }
    const exactPosRatio = target.length === 0 ? 0 : exactMatches / target.length;

    // LCS ratio (sequence similarity, ignores extra padding or missing tokens)
    const lcsLen = lcsLength(observed, target);
    const lcsRatio = target.length === 0 ? 0 : lcsLen / target.length;

    // penalty for mismatched NOP counts (optional)
    // We'll slightly downweight if observed has many extra NOPs beyond signature (avoids false positives)
    const observedNOPs = observed.filter(x => x === 'NOP').length;
    const targetNOPs = target.filter(x => x === 'NOP').length;
    const nopPenalty = observedNOPs > targetNOPs ? Math.min(0.05, (observedNOPs - targetNOPs) * 0.02) : 0;

    // combine into a single score (0..100)
    const combined = (weights.lcsWeight * lcsRatio + weights.exactPosWeight * exactPosRatio - nopPenalty);
    const score = Math.max(0, Math.min(1, combined)) * 100;

    // flagged match if score > threshold (you can tune)
    const matched = score >= (opts.threshold ?? 45);

    return {
        id: signature.id,
        name: signature.name,
        score: Math.round(score * 100) / 100, // two decimals
        matched,
        details: {
            observed,
            target,
            exactMatches,
            exactPosRatio: Math.round(exactPosRatio * 10000) / 100,
            lcsLen,
            lcsRatio: Math.round(lcsRatio * 10000) / 100,
            targetLength: target.length,
            observedLength: observed.length,
            nopPenalty
        }
    };
}

// === helpers to run all signatures and sort results ===
function matchAllSignatures(observedRaw, signatures, opts) {
    const results = signatures.map(sig => matchSignature(observedRaw, sig, opts));
    results.sort((a, b) => b.score - a.score);
    return results;
}
function printTopOlayoutSignatures(scoreResults, olayoutSignatures) {
    if (!Array.isArray(scoreResults) || scoreResults.length === 0) {
        throw new Error("Expected a non-empty array of score results.");
    }
    if (!Array.isArray(olayoutSignatures) || olayoutSignatures.length === 0) {
        throw new Error("Expected a non-empty array of olayout signatures.");
    }

    // Find highest score
    const highestScore = Math.max(...scoreResults.map(sig => sig.score));

    // Get all result entries that share the highest score
    const topResults = scoreResults.filter(sig => sig.score === highestScore);

    console.log(`🏆 Highest Score: ${highestScore}\n`);

    // Match and print corresponding olayout signatures
    topResults.forEach(result => {
        const match = olayoutSignatures.find(o => o.id === result.id);
        if (match) {
            console.log(`🆔 ${match.id}: ${match.name}`);
            console.log(`🧠 Likely OS: ${match.likelyOS.join(", ")}`);
            console.log(`📜 Description: ${match.description}`);
            console.log("──────────────────────────────");
        } else {
            console.log(`⚠️ No olayoutSignature found for ${result.id}`);
        }
    });

    return { highestScore, topResults };
}

function getHighestScoreSignatures(signatures) {
    if (!Array.isArray(signatures) || signatures.length === 0) {
        throw new Error("Expected a non-empty array of signatures.");
    }

    // Find the highest score
    const highestScore = Math.max(...signatures.map(sig => sig.score));

    // Filter all signatures that have this score
    const topSignatures = signatures.filter(sig => sig.score === highestScore);

    console.log("Highest Score:", highestScore);
    console.log("Signatures with Highest Score:", topSignatures);

    return { highestScore, topSignatures };
}

/**
 * Normalizes and converts an array of TCP options into a standard signature string.
 * E.g., ['MSS', 'NOP', 'NOP', 'Timestamps'] becomes "MNNTS".
 * @param {string[]} ordering - The array of options from the packet.
 * @returns {string} The normalized signature string.
 */
function getSignatureString(ordering) {
    const normalize = (opt) => {
        const upperOpt = opt.toUpperCase();
        if (upperOpt === 'TIMESTAMPS' || upperOpt === 'TS') return 'T';
        if (upperOpt === 'SACK' || upperOpt === 'SACKOK') return 'S';
        if (upperOpt === 'WSCALE' || upperOpt === 'WINDOW SCALE') return 'W';
        if (upperOpt === 'MSS') return 'M';
        if (upperOpt === 'NOP') return 'N';
        if (upperOpt === 'EOL') return 'E';
        return 'L'; // 'L' for unknown/other
    };
    return ordering.map(normalize).join('');
}

/**
 * Finds all matching OS signatures for a given captured option ordering.
 * @param {string[]} capturedOrdering - The array of options from the target.
 * @param {object} patternsDB - The responsePatterns database object.
 * @returns {object[]} An array of all matches found.
 */
function findMatchingSignatures(capturedOrdering, patternsDB) {
    const signatureString = getSignatureString(capturedOrdering);
    const matches = [];

    console.log(`Searching for signature: "${signatureString}"`);

    // Iterate through each OS family in the database
    for (const [osFamily, patternData] of Object.entries(patternsDB)) {
        // Iterate through each O-pattern (O1 to O6) for that OS
        for (const [oKey, validResponses] of Object.entries(patternData.o_pattern)) {
            // Check if our signature string is in the list of valid responses
            if (validResponses.includes(signatureString)) {
                matches.push({
                    os: osFamily,
                    description: patternData.description,
                    matchedOn: oKey, // Which probe response it matched (O1, O2, etc.)
                    pattern: signatureString,
                    confidence: patternData.confidence,
                    notes: patternData.notes
                });
            }
        }
    }

    return matches;
}




module.exports = { extractOptions, matchAllSignatures, printTopOlayoutSignatures, getHighestScoreSignatures, olayoutSignatures, matchSignature }