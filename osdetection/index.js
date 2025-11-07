const NmapProbeOptions = require("../utils/tcp/tcp-option-probes");
const { tcp, ipv4 } = require("netcraft-js")

function buildTcpOs(srcIp, destIp, srcPort, destPort) {
    const AllProbesArray = [
        NmapProbeOptions.P1_OPTION,
        NmapProbeOptions.P2_OPTION,
        NmapProbeOptions.P3_OPTION,
        NmapProbeOptions.P4_OPTION,
        NmapProbeOptions.P5_OPTION,
        NmapProbeOptions.P6_OPTION
    ];
    return AllProbesArray.map(probe => {
        return tcp.Encode(srcIp, destIp, srcPort, destPort, 0, 0, { syn: true }, 65535, 0, probe);
    })
}

async function tcpProbeDecode(sourceIP, targetIP) {
    console.log(`Starting tcp probe sweep on tarhet: ${targetIP}.0/24`);
    const tcpPackets = buildTcpOs(sourceIP, targetIP, 33109, 53);
    const promises = [];

    // tcpPackets.map(tcpPacket => {
    //     promises.push(sendPacketAndDecode(sourceIP, targetIP, 53, 1000, tcpPacket));
    // })

    promises.push(sendPacketAndDecode(sourceIP, targetIP, 53, 1000, tcpPackets[0]))

    // tcpPackets.forEach(probe => {
    //     promises.push(sendPacketAndListen(sourceIP, targetIP, 80, 53, probe));
    // })

    const results = await Promise.all(promises);

    let options = extractOptions(results[0]?.decoded?.options);

    let captured = {
        options,
        window_size: results[0]?.decoded.windowSize
    }

    console.log(matchOSFingerprint(captured), results[0]?.decoded);

    // console.log(printTopOlayoutSignatures(matchAllSignatures(options, olayoutSignatures), olayoutSignatures), 'olayoutSignatures')


    // console.log(findMatchingSignatures(options, responsePatterns))

    console.log("probe sweep complete!");
}