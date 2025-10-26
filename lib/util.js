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
