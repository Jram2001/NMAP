const tcpCheck = require('../utils/tcp.util').tcpCheck;
const sendPacketAndListen = require('../utils/tcp.util').sendPacketAndListen;
const NmapProbeOptions = require("../utils/tcp/tcp-option-probes");
const { Encode } = require("../utils/tcp/tcp");
const sendPacketAndDecode = require('../utils/tcp.util').sendPacketAndDecode;
const { matchAllSignatures, extractOptions, printTopOlayoutSignatures, getHighestScoreSignatures, olayoutSignatures } = require("../lib/util")
async function tcpSweep(subnet) {
    console.log(`Starting tcp sweep on subnet: ${subnet}.0/24`);

    const commonPorts = [22, 53, 80, 443, 8080, 3128];
    const promises = [];

    for (let i = 1; i < 255; i++) {
        for (let port of commonPorts) {
            promises.push(tcpCheck(`${subnet}.${i}`, port));
        }
    }

    const results = await Promise.all(promises);

    // Group results by host
    const grouped = {};

    results
        .filter(r => r.status === 'open' || r.status === 'closed')
        .forEach(r => {
            if (!grouped[r.host]) grouped[r.host] = [];
            grouped[r.host].push(`${r.port} (${r.status})`);
        });

    console.log("tcp sweep complete!");

    // Print summary
    Object.entries(grouped).forEach(([host, ports]) => {
        console.log(`${host} → ${ports.join(', ')}`);
    });
}

async function findTcpPorts(host, commonPorts = [2121, 53, 80, 443, 8080, 8443, 22, 23, 3389, 5900, 25, 110, 143, 465, 587, 993, 995, 20, 21, 139, 445, 1433, 3306, 5432, 6379, 27017, 135, 1723, 1521, 8081]) {
    console.log(`Starting tcp sweep on host: ${host}`);

    const promises = [];

    for (let port of commonPorts) {
        promises.push(tcpCheck(host, port));
    }

    const results = await Promise.all(promises);

    // Group results by host
    const grouped = {};

    results
        .filter(r => r.status === 'open' || r.status === 'closed')
        .forEach(r => {
            if (!grouped[r.host]) grouped[r.host] = [];
            grouped[r.host].push(`${r.port} (${r.status})`);
        });

    console.log("tcp sweep complete!");

    // Print summary
    Object.entries(grouped).forEach(([host, ports]) => {
        console.log(`${host} → ${ports.join(', ')}`);
    });
}


async function findAllTcpPorts(host) {
    console.log(`Starting tcp sweep on host: ${host}`);

    const promises = [];

    for (let index = 0; index < 65535; index++) {
        promises.push(tcpCheck(host, index));
    }

    const results = await Promise.all(promises);

    // Group results by host
    const grouped = {};

    results
        .filter(r => r.status === 'open')
        .forEach(r => {
            if (!grouped[r.host]) grouped[r.host] = [];
            grouped[r.host].push(`${r.port} (${r.status})`);
        });

    console.log("tcp sweep complete!");

    // Print summary
    Object.entries(grouped).forEach(([host, ports]) => {
        console.log(`${host} → ${ports.join(', ')}`);
    });
}

function buildTcp(srcIp, destIp, srcPort, destPort) {
    const AllProbesArray = Object.values(NmapProbeOptions);
    const flags = { syn: true };
    return AllProbesArray.map(probe => {
        // console.log(buildTcpPacket(srcIp, destIp, srcPort, destPort, 0, 0, { syn: true }, 65535, probe))
        return Encode(srcIp, destIp, srcPort, destPort, 0, 0, { syn: true }, 65535, 0, probe);
    })
}

async function tcpProbeSweep(sourceIP, targetIP) {
    console.log(`Starting tcp probe sweep on tarhet: ${targetIP}.0/24`);
    const tcpPackets = buildTcp(sourceIP, targetIP, 33109, 53);
    const promises = [];

    //Temprory
    // promises.push(sendPacketAndListen(sourceIP, targetIP, 53, 1000, tcpPackets));

    promises.push(sendPacketAndListen(sourceIP, targetIP, 53, 1000, tcpPackets[0]));
    // promises.push(sendPacketAndListen(sourceIP, targetIP, 53, 1000, tcpPackets[1]));
    // promises.push(sendPacketAndListen(sourceIP, targetIP, 53, 1000, tcpPackets[2]));


    // tcpPackets.forEach(probe => {
    //     promises.push(sendPacketAndListen(sourceIP, targetIP, 80, 53, probe));
    // })

    const results = await Promise.all(promises);

    console.log("probe sweep complete!");
}

async function tcpProbeDecode(sourceIP, targetIP) {
    console.log(`Starting tcp probe sweep on tarhet: ${targetIP}.0/24`);
    const tcpPackets = buildTcp(sourceIP, targetIP, 33109, 53);
    const promises = [];

    //Temprory
    // promises.push(sendPacketAndListen(sourceIP, targetIP, 53, 1000, tcpPackets));

    promises.push(sendPacketAndDecode(sourceIP, targetIP, 53, 1000, tcpPackets[0]));
    // promises.push(sendPacketAndListen(sourceIP, targetIP, 53, 1000, tcpPackets[1]));
    // promises.push(sendPacketAndListen(sourceIP, targetIP, 53, 1000, tcpPackets[2]));


    // tcpPackets.forEach(probe => {
    //     promises.push(sendPacketAndListen(sourceIP, targetIP, 80, 53, probe));
    // })

    const results = await Promise.all(promises);

    let options = extractOptions(results[0]?.decoded?.options);

    console.log(matchAllSignatures(options, olayoutSignatures), Array.isArray(matchAllSignatures(options, olayoutSignatures)));
    console.log(printTopOlayoutSignatures(matchAllSignatures(options, olayoutSignatures), olayoutSignatures), 'olayoutSignatures')

    console.log("probe sweep complete!", options);
}



module.exports = { tcpSweep, findTcpPorts, findAllTcpPorts, tcpProbeSweep, tcpProbeDecode };
