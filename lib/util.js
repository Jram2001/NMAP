const olayoutSignatures = [
    {
        id: "sig-1",
        olayout: ["MSS", "NOP", "NOP", "TS"],
        name: "MSS → NOP → NOP → TS",
        description: "Very common Linux / Linux-based devices (also many Android / embedded Linux). Two NOPs used for padding before TS.",
        likelyOS: ["Linux", "Embedded Linux", "Android"],
        confidence: 75,
        notes: "High-signal for Linux-family stacks but not exclusive; middleboxes can alter ordering."
    },
    {
        id: "sig-2",
        olayout: ["WSCALE", "NOP", "MSS", "SACKOK", "NOP", "NOP"],
        name: "WSCALE → NOP → MSS → SACKOK → NOP → NOP",
        description: "Seen in Windows-like stacks and some active-probe responses; WSCALE early in the layout is a Windows-ish hint.",
        likelyOS: ["Windows", "Windows Server", "Some network libraries"],
        confidence: 65,
        notes: "Nmap uses similar probes; windows versions and config can vary, lowering absolute certainty."
    },
    {
        id: "sig-3",
        olayout: ["MSS", "SACKOK", "TS", "NOP"],
        name: "MSS → SACKOK → TS → NOP",
        description: "Common BSD/macOS and certain Unix variants — SACKOK early, TS following.",
        likelyOS: ["FreeBSD", "OpenBSD", "macOS", "Other BSDs"],
        confidence: 60,
        notes: "BSDs often differ in padding and may omit terminal NOP; treat as a heuristic, not definitive."
    },
    {
        id: "sig-4",
        olayout: ["MSS", "WSCALE", "SACKOK", "TS"],
        name: "MSS → WSCALE → SACKOK → TS",
        description: "A full-option ordering found on many modern stacks that advertise all common options.",
        likelyOS: ["Modern Linux", "Modern BSDs", "Network gear"],
        confidence: 55,
        notes: "Permutation of the same four options — presence of all four is more informative than strict order."
    },
    {
        id: "sig-5",
        olayout: ["MSS", "TS"],
        name: "MSS → TS",
        description: "Minimal ordering — no WSCALE or SACKOK. Seen on older Unix variants or trimmed/embedded stacks.",
        likelyOS: ["Older Unix", "Simple embedded stacks", "IoT devices"],
        confidence: 50,
        notes: "Short olayouts are ambiguous; combine with other metrics (TTL, window) for better ID."
    },
    {
        id: "sig-6",
        olayout: ["WSCALE", "MSS", "SACKOK", "TS", "NOP"],
        name: "WSCALE → MSS → SACKOK → TS → NOP",
        description: "Alternative ordering with WS early — appears in some stacks and when middleboxes intervene.",
        likelyOS: ["Windows variants", "Router/firmware stacks", "Middlebox-modified"],
        confidence: 45,
        notes: "Because of the WS first placement, often suspicious for Windows-like or modified stacks; low certainty if middleboxes are present."
    },
    {
        id: "sig-7",
        olayout: ["MSS", "NOP", "SACKOK", "TS", "NOP"],
        name: "MSS → NOP → SACKOK → TS → NOP",
        description: "Mixed pattern where NOPs are used for padding between multi-byte options; common across many OSes.",
        likelyOS: ["Linux", "BSD", "Embedded"],
        confidence: 50,
        notes: "NOPs are padding — this pattern appears in multiple vendors; use as part of multi-field fingerprinting."
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



module.exports = { extractOptions, matchAllSignatures, printTopOlayoutSignatures, getHighestScoreSignatures, olayoutSignatures, matchSignature }