const NmapProbeOptions = require("../utils/tcp/tcp-option-probes");
const { tcp, ipv4 } = require('netcraft-js');
const { NmapProbeGenerator } = require('./options');
const raw = require("raw-socket");
const { buildTn, convertToNmapOPSFingerprint, extractWindowFingerprint } = require('./finger-printing');

// Configuration
const TARGET_IP = "192.168.0.1";
const SOURCE_IP = "192.168.0.195";
const SOURCE_PORT = 12340;
const TARGET_PORT = 53;
const IDLE_TIMEOUT_MS = 3000;
const CHECK_INTERVAL_MS = 100;

// State management
let packetsFromTarget = {};
let lastResponseTime = Date.now();
let checkInterval;

/**
 * Initialize probe generator and create all TCP probes
 */
const probesGenerator = new NmapProbeGenerator(
    SOURCE_IP,
    TARGET_IP,
    SOURCE_PORT,
    TARGET_PORT
);
const probes = probesGenerator.generateAllProbes();

/**
 * Send TCP/IP probes via raw socket and collect responses
 */
function sendProbes() {
    const socket = raw.createSocket({ protocol: raw.Protocol.TCP });

    // Handle incoming packets
    socket.on("message", (buffer) => {
        const ipv4Result = ipv4.DecodeHeader(buffer);
        const tcpResult = tcp.Decode(ipv4Result.payload);

        // Filter packets from target IP
        if (ipv4Result.srcIp === TARGET_IP) {
            const probeIndex = 1 + (tcpResult.destinationPort % SOURCE_PORT);

            packetsFromTarget[probeIndex] = {
                rawData: buffer,
                ipv4: ipv4Result,
                tcp: tcpResult
            };

            lastResponseTime = Date.now();
        }
    });

    // Send all probes
    for (const probe of probes) {

        socket.send(probe.tcpHeader, 0, probe.tcpHeader.length, TARGET_IP, (err) => {
            if (err) {
                console.error("Error sending probe:", err);
            }
        });
    }

    // Monitor for completion (idle timeout)
    checkInterval = setInterval(() => {
        const timeSinceLastResponse = Date.now() - lastResponseTime;

        if (timeSinceLastResponse >= IDLE_TIMEOUT_MS) {
            clearInterval(checkInterval);
            onComplete(socket);
        }
    }, CHECK_INTERVAL_MS);
}


/**
 * Handle completion of packet collection
 * @param {Object} socket - The raw socket instance
 */
function onComplete(socket) {
    console.log("\n=== Collection Complete (Idle Timeout) ===");
    console.log(`Received ${Object.keys(packetsFromTarget).length}/${probes.length} responses`);

    socket.close();
    for (let i = 0; i < probes.length; i++) {
        if (packetsFromTarget[i]) {
            console.log(buildTn(packetsFromTarget[i].tcp, packetsFromTarget[i].ipv4, 'T' + packetsFromTarget[i].tcp.destinationPort % 12340, 0));
        } else {
            console.log(`T${1}(R=N)`);
        }
    }

    // TODO: Uncomment when ready to process fingerprint
    // processFingerprint();
}

// Execute probe scanning
sendProbes();