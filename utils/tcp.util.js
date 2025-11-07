const net = require("net");
const raw = require("raw-socket");
const { Decode } = require("./tcp/tcp");
const TcpPacket = require("tcp-packet");
const { ipv4 } = require("netcraft-js")
function tcpCheck(host, port = 80, timeout = 1000) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(timeout);

        socket.on("connect", () => {
            socket.destroy();
            resolve({ host, port, status: "open" });
        });

        socket.on("error", (err) => {
            socket.destroy();
            if (err.code === "ECONNREFUSED") {
                resolve({ host, port, status: "closed" }); // alive, but no service
            } else {
                resolve({ host, port, status: "filtered_or_down" }); // no reply
            }
        });

        socket.on("timeout", () => {
            socket.destroy();
            resolve({ host, port, status: "timeout" });
        });

        socket.connect(port, host);
    });
}

function grabBanner(host, port = 80, timeout = 1000) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        let banner = '';
        socket.setTimeout(timeout);

        socket.on("connect", () => {
            // socket.destroy();
            // resolve({ host, port, status: "open", banner: banner || "No banner" });
        });

        socket.on("data", (data) => {
            banner += data.toString();
            socket.destroy();
            resolve({ host, port, status: "open", banner });
        });

        socket.on("error", (err) => {
            socket.destroy();
            if (err.code === "ECONNREFUSED") {
                resolve({ host, port, status: "closed", banner: null });
            } else {
                resolve({ host, port, status: "filtered_or_down", banner: null });
            }
        });

        socket.on("timeout", () => {
            socket.destroy();
            resolve({ host, port, status: "timeout", banner: null });
        });

        socket.connect(port, host);
    });
}

function sendTcpProbes(targetIP, port = 80, timeout = 1000) {
    const socket = raw.createSocket({ protocol: raw.Protocol.TCP });
    function createTcpProbe(flags, seq = 0, ack = 0, window = 1024) {
        return TcpPacket.encode({
            sourcePort: 1234,
            destinationPort: 53,
            sequenceNumber: seq,
            acknowledgmentNumber: ack,
            flags,
            windowSize: window,
            data: Buffer.from([]),
        });
    }

    socket.on("message", (buffer) => {
        const result = TcpPacket.decode(buffer);
        console.log("TCP Probes Result", result.data.toString('hex'))
        // console.log('Messsage from target', buffer.toString())
    });

    const probes = [
        { syn: true },                  // SYN
        { fin: true },                  // FIN
        { fin: true, psh: true, urg: true }, // Xmas
        { ack: true },                  // ACK
    ];

    for (const flags of probes) {
        const packet = createTcpProbe(flags);
        socket.send(packet, 0, packet.length, targetIP, function (err, bytes) {
            if (err) console.error(err);
            else {
                console.log("Probe sent with flags:", flags);
            };
        });
    }
}

function sendPacketAndListen(sourceIP, targetIP, port = 80, timeout = 1000, tcpPacket) {
    return new Promise((resolve) => {

        const socket = raw.createSocket({ protocol: raw.Protocol.TCP });

        console.log(`Sending TCP packet to ${targetIP}...`);

        console.log(tcpPacket, 'tcpPacket');

        // Send raw TCP packet immediately
        socket.send(tcpPacket, 0, tcpPacket.length, targetIP, function (err, bytes) {
            if (err) {
                console.error("Send error:", err);
                socket.close();
                resolve({ host: targetIP, status: "send_error" });
            } else {
                console.log("TCP packet sent successfully:", bytes, "bytes");
            }
        });

        // Listen for replies
        socket.on('message', (buffer, source) => {
            if (source !== targetIP) return;

            // Basic TCP header parsing
            const srcPort = buffer.readUInt16BE(0);
            const dstPort = buffer.readUInt16BE(2);
            const flags = buffer.readUInt8(13);
            const decoded = Decode(buffer, true);
            console.log(`Packet from ${source} - srcPort:${srcPort} dstPort:${dstPort} flags:0x${flags.toString(16)}`, decoded);

            // Example: detect SYN-ACK
            if ((flags & 0x12) === 0x12) {
                socket.close();
                resolve({ host: targetIP, status: "open" });
            } else if (flags & 0x04) {
                socket.close();
                resolve({ host: targetIP, status: "closed" });
            }
        });

        // Timeout handler
        setTimeout(() => {
            console.log("No reply received - timeout");
            socket.close();
            resolve({ host: targetIP, status: "filtered_or_no_response" });
        }, timeout);

        socket.on('error', (err) => {
            console.error("Socket error:", err);
            socket.close();
            resolve({ host: targetIP, status: "error" });
        });
    });
};

function sendPacketAndDecode(sourceIP, targetIP, port = 80, timeout = 1000, tcpPacket) {
    return new Promise((resolve) => {
        const socket = raw.createSocket({ protocol: raw.Protocol.TCP });
        let resolved = false;

        const safeResolve = (value) => {
            if (!resolved) {
                resolved = true;
                socket.close();
                resolve(value);
            }
        };

        console.log(`Sending TCP Packet to ${targetIP}`);

        socket.send(tcpPacket, 0, tcpPacket.length, targetIP, (err, bytes) => {
            if (err) {
                console.error("Send error", err);
                safeResolve({ error: err });
            }
        });

        socket.on('message', (buffer, source) => {
            if (source !== targetIP) return;
            const DecodeIP = ipv4.DecodeHeader(buffer);
            console.log(DecodeIP, 'DecodeIP')
            const decoded = Decode(buffer, true);
            safeResolve({ decoded });
        });

        const timer = setTimeout(() => {
            console.log("No reply received - timeout");
            safeResolve({ host: targetIP, status: "filtered_or_no_response" });
        }, timeout);

        socket.on('error', (err) => {
            console.error("Socket error:", err);
            safeResolve({ host: targetIP, status: "error", error: err });
        });
    });
}

module.exports = { tcpCheck, grabBanner, sendTcpProbes, sendPacketAndListen, sendPacketAndDecode }
