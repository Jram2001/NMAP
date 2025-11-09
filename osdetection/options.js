const { optEOL, optNOP, optMSS, optWScale, optSACK, optTimestamp, optPadding } = require('../utils/tcp/option-bulder');
const { tcp, ipv4 } = require('netcraft-js');
let counter = 0;
class NmapProbeGenerator {
    constructor(srcIp, destIp, srcPort, destPort) {
        this.srcIp = srcIp;
        this.destIp = destIp;
        this.srcPort = srcPort;
        this.destPort = destPort;
    }

    /**
     * Generate a complete packet (IP header + TCP header)
     * The TCP packet becomes the payload for the IP packet
     */
    generatePacket(probeName, tcpFlags, tcpOptions = Buffer.alloc(0)) {
        // Step 1: Create TCP header+options
        const tcpHeader = tcp.Encode(
            this.srcIp,
            this.destIp,
            this.srcPort,
            this.destPort,
            0,                      // seqNumber
            0,                      // ackNumber (0 for SYN packets)
            tcpFlags,              // TCP flags
            65535,                 // windowSize
            0,                     // urgentPointer
            tcpOptions,            // TCP options
            Buffer.alloc(0)        // TCP data/payload
        );

        // Step 2: Create IP header with TCP header as payload
        const ipPacket = ipv4.Encode(
            this.srcIp,
            this.destIp,
            4,                                      // version
            0,                                      // DSCP
            0,                                      // ECN
            Math.floor(Math.random() * 65536),     // identification
            'DF',                                 // flags
            0,                                      // fragmentOffset
            64,                                     // ttl
            'tcp',                                      // protocol (TCP)
            false,                                  // no IP options
            tcpHeader                              // TCP header becomes IP payload ← KEY!
        );

        return {
            name: probeName,
            ipPacket: ipPacket,
            tcpHeader: tcpHeader,
            totalSize: ipPacket.length
        };
    }

    /**
     * T1 Probe - Standard SYN with full options
     */
    generateT1() {
        const options = optPadding(Buffer.concat([
            optMSS(1460),
            optWScale(10),
            optNOP(),
            optTimestamp(),
            optSACK(),
            optEOL()
        ]));

        return this.generatePacket('T1', { syn: true }, options);
    }

    /**
     * T2 Probe - NULL flags
     */
    generateT2() {
        return this.generatePacket('T2', {}, Buffer.alloc(0));
    }

    /**
     * T3 Probe - SYN+FIN+URG+PSH
     */
    generateT3() {
        return this.generatePacket('T3', { syn: true, fin: true, urg: true, psh: true }, Buffer.alloc(0));
    }

    /**
     * T4 Probe - ACK
     */
    generateT4() {
        return this.generatePacket('T4', { ack: true }, Buffer.alloc(0));
    }

    /**
     * T5 Probe - SYN (no options)
     */
    generateT5() {
        return this.generatePacket('T5', { syn: true }, Buffer.alloc(0));
    }

    /**
     * T6 Probe - ACK (no options)
     */
    generateT6() {
        return this.generatePacket('T5', { ack: true }, Buffer.alloc(0));
    }

    /**
     * T7 Probe - FIN+PSH+URG
     */
    generateT7() {
        return this.generatePacket('T7', { fin: true, psh: true, urg: true }, Buffer.alloc(0));
    }

    /**
     * ECN Probe - SYN with ECE and CWR flags
     */
    generateECN() {
        const options = optPadding(Buffer.concat([
            optMSS(1460),
            optWScale(10),
            optNOP(),
            optTimestamp(),
            optSACK(),
            optEOL()
        ]));

        return this.generatePacket('ECN', { syn: true, ece: true, cwr: true }, options);
    }

    /**
     * Generate all 7 probes + ECN
     */
    generateAllProbes() {
        return [
            this.generateT1(),
            this.generateT2(),
            this.generateT3(),
            this.generateT4(),
            this.generateT5(),
            this.generateT6(),
            this.generateT7(),
            this.generateECN()
        ];
    }
}

// Usage:
// const generator = new NmapProbeGenerator(
//     '10.52.155.1',      // srcIp
//     '10.52.155.214',    // destIp (target)
//     12345,              // srcPort
//     80                  // destPort
// );

// const probes = generator.generateAllProbes();

// probes.forEach(probe => {
//     console.log(`Probe: ${probe.name}`);
//     console.log(`  Total packet size: ${probe.totalSize} bytes`);
//     console.log(`  IP packet (hex): ${probe.ipPacket.toString('hex').substring(0, 40)}...`);
//     console.log(`  TCP header (hex): ${probe.tcpHeader.toString('hex').substring(0, 40)}...`);
// });

module.exports = { NmapProbeGenerator };
