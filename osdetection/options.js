const { optEOL, optNOP, optMSS, optWScale, optSACK, optTimestamp, optPadding } = require('./tcpOptions');
const { tcp, ipv4 } = require('netcraft-js')
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
            'DFMF',               // flags
            0,                                      // fragmentOffset
            64,                                     // ttl
            6,                                      // protocol (TCP)
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
        // For ACK probe, we need non-zero ACK number
        const tcpHeader = Encode(
            this.srcIp,
            this.destIp,
            this.srcPort,
            this.destPort,
            0,
            1000,  // Non-zero ACK number
            { ack: true },
            65535,
            0,
            Buffer.alloc(0),
            Buffer.alloc(0)
        );

        const ipPacket = Encode(
            this.srcIp,
            this.destIp,
            4, 0, 0,
            Math.floor(Math.random() * 65536),
            { DF: true, MF: false },
            0, 64, 6, false,
            tcpHeader  // TCP as IP payload
        );

        return {
            name: 'T4',
            ipPacket: ipPacket,
            tcpHeader: tcpHeader,
            totalSize: ipPacket.length
        };
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
        const tcpHeader = Encode(
            this.srcIp,
            this.destIp,
            this.srcPort,
            this.destPort,
            0,
            1000,
            { ack: true },
            65535,
            0,
            Buffer.alloc(0),
            Buffer.alloc(0)
        );

        const ipPacket = Encode(
            this.srcIp,
            this.destIp,
            4, 0, 0,
            Math.floor(Math.random() * 65536),
            { DF: true, MF: false },
            0, 64, 6, false,
            tcpHeader
        );

        return {
            name: 'T6',
            ipPacket: ipPacket,
            tcpHeader: tcpHeader,
            totalSize: ipPacket.length
        };
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
const generator = new NmapProbeGenerator(
    '10.52.155.1',      // srcIp
    '10.52.155.214',    // destIp (target)
    12345,              // srcPort
    80                  // destPort
);

const probes = generator.generateAllProbes();

probes.forEach(probe => {
    console.log(`Probe: ${probe.name}`);
    console.log(`  Total packet size: ${probe.totalSize} bytes`);
    console.log(`  IP packet (hex): ${probe.ipPacket.toString('hex').substring(0, 40)}...`);
    console.log(`  TCP header (hex): ${probe.tcpHeader.toString('hex').substring(0, 40)}...`);
});

module.exports = NmapProbeGenerator;
