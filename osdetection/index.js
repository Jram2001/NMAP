const NmapProbeOptions = require("../utils/tcp/tcp-option-probes");
const { tcp, ipv4, udp } = require('netcraft-js');
const { NmapProbeGenerator } = require('./options');
const raw = require("raw-socket");
const {
    buildTn,
    convertToNmapOPSFingerprint,
    extractWindowFingerprint
} = require('./finger-printing');

/**
 * TCP Scanner Class for Nmap-style OS Detection
 */
class TCPScanner {
    constructor(config) {
        this.config = {
            targetIp: config.targetIp,
            sourceIp: config.sourceIp,
            sourcePort: config.sourcePort,
            targetPort: config.targetPort,
            idleTimeoutMs: config.idleTimeoutMs || 3000,
            checkIntervalMs: config.checkIntervalMs || 100
        };

        this.packetsFromTarget = {};
        this.lastResponseTime = Date.now();
        this.checkInterval = null;
        this.socket = null;
        this.probes = [];
        this.probesGenerator = null;
        this.udpProbe = [];
    }

    /**
     * Initialize the probe generator and create all TCP probes
     */
    initialize() {
        try {
            this.probesGenerator = new NmapProbeGenerator(
                this.config.sourceIp,
                this.config.targetIp,
                this.config.sourcePort,
                this.config.targetPort
            );
            this.probes = this.probesGenerator.generateAllProbes();
            console.log(`Initialized ${this.probes.length} probes`);
        } catch (error) {
            throw new Error(`Failed to initialize probes: ${error.message}`);
        }
    }

    /**
     * Handle incoming packets
     * @param {Buffer} buffer - Raw packet buffer
     */
    handleIncomingPacket(buffer) {
        try {
            const ipv4Result = ipv4.DecodeHeader(buffer);
            const tcpResult = tcp.Decode(ipv4Result.payload);

            // Filter packets from target IP only
            if (ipv4Result.srcIp === this.config.targetIp) {
                const probeIndex = 1 + (tcpResult.destinationPort % this.config.sourcePort);

                this.packetsFromTarget[probeIndex] = {
                    rawData: buffer,
                    ipv4: ipv4Result,
                    tcp: tcpResult,
                    timestamp: Date.now()
                };

                this.lastResponseTime = Date.now();

                if (this.config.verbose) {
                    console.log(`Received response for probe ${probeIndex}`);
                }
            }
        } catch (error) {
            console.error("Error processing incoming packet:", error.message);
        }
    }

    /**
     * Send a single probe
     * @param {Object} probe - Probe object with TCP header
     * @param {number} index - Probe index
     * @returns {Promise}
     */
    sendProbe(probe, index) {
        return new Promise((resolve, reject) => {
            this.socket.send(
                probe.tcpHeader,
                0,
                probe.tcpHeader.length,
                this.config.targetIp,
                (err) => {
                    if (err) {
                        console.error(`Error sending probe ${index}:`, err.message);
                        reject(err);
                    } else {
                        if (this.config.verbose) {
                            console.log(`Sent probe ${index}`);
                        }
                        resolve();
                    }
                }
            );
        });
    }

    /**
     * Send all TCP probes sequentially
     */
    async sendAllProbes() {
        console.log(`Sending ${this.probes.length} probes...`);

        for (let i = 0; i < this.probes.length; i++) {
            try {
                await this.sendProbe(this.probes[i], i + 1);
                // Optional: Add small delay between probes
                // await this.delay(10);
            } catch (error) {
                console.error(`Failed to send probe ${i + 1}`);
            }
        }

        console.log("All probes sent");
    }

    /**
     * Delay helper
     * @param {number} ms - Milliseconds to delay
     */
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Start monitoring for idle timeout
     */
    startIdleMonitor() {
        this.checkInterval = setInterval(() => {
            const timeSinceLastResponse = Date.now() - this.lastResponseTime;

            if (timeSinceLastResponse >= this.config.idleTimeoutMs) {
                this.stopScan();
            }
        }, this.config.checkIntervalMs);
    }

    /**
     * Stop the scan and process results
     */
    stopScan() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }

        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }

        this.processResults();
    }

    /**
     * Process and display results
     */
    processResults() {
        console.log("\n=== Scan Complete (Idle Timeout) ===");
        console.log(`Received ${Object.keys(this.packetsFromTarget).length}/${this.probes.length} responses\n`);

        const results = [];

        for (let i = 1; i <= this.probes.length; i++) {
            if (this.packetsFromTarget[i]) {
                const packet = this.packetsFromTarget[i];
                const probeType = `T${packet.tcp.destinationPort % this.config.sourcePort}`;
                const fingerprint = buildTn(packet.tcp, packet.ipv4, probeType, 0);

                console.log(fingerprint);
                results.push({
                    probeIndex: i,
                    probeType,
                    fingerprint,
                    received: true
                });
            } else {
                console.log(`T${i}(R=N)`);
                results.push({
                    probeIndex: i,
                    probeType: `T${i}`,
                    fingerprint: null,
                    received: false
                });
            }
        }

        this.displaySummary(results);
    }

    /**
     * Display scan summary
     * @param {Array} results - Array of result objects
     */
    displaySummary(results) {
        console.log("\n=== Scan Summary ===");
        const received = results.filter(r => r.received).length;
        const missed = results.filter(r => !r.received).length;

        console.log(`Total Probes: ${results.length}`);
        console.log(`Responses Received: ${received}`);
        console.log(`No Response: ${missed}`);
        console.log(`Success Rate: ${((received / results.length) * 100).toFixed(2)}%`);
    }

    /**
     * Run the complete scan
     */
    async run() {
        try {
            // Initialize probes
            this.initialize();

            // Create raw socket
            this.socket = raw.createSocket({ protocol: raw.Protocol.TCP });

            // Set up packet handler
            this.socket.on("message", (buffer) => this.handleIncomingPacket(buffer));

            // Handle socket errors
            this.socket.on("error", (error) => {
                console.error("Socket error:", error.message);
                this.stopScan();
            });

            // Start idle monitor
            this.startIdleMonitor();

            // Send all probes
            await this.sendAllProbes();

            console.log("\nWaiting for responses...");

        } catch (error) {
            console.error("Scan failed:", error.message);
            this.cleanup();
        }
    }

    /**
     * Cleanup resources
     */
    cleanup() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
        }
        if (this.socket) {
            try {
                this.socket.close();
            } catch (error) {
                console.error("Error closing socket:", error.message);
            }
        }
    }
}

// Configuration
const scanConfig = {
    targetIp: "10.168.25.89",
    sourceIp: "10.168.25.214",
    sourcePort: 12340,
    targetPort: 53,
    idleTimeoutMs: 3000,
    checkIntervalMs: 100,
    verbose: false
};

// Create and run scanner
const scanner = new TCPScanner(scanConfig);

// Handle process termination
process.on('SIGINT', () => {
    console.log("\n\nScan interrupted by user");
    scanner.cleanup();
    process.exit(0);
});

process.on('uncaughtException', (error) => {
    console.error("Uncaught exception:", error);
    scanner.cleanup();
    process.exit(1);
});

// Execute the scan
scanner.run().catch(error => {
    console.error("Fatal error:", error);
    scanner.cleanup();
    process.exit(1);
});