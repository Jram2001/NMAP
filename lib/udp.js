const udpCheck = require('../utils/udp.util').udpCheck;

async function udpSweep(subnet) {
    console.log(`Starting udp sweep on subnet: ${subnet}.0/24`);

    const commonPorts = [53, 67, 68, 69, 123, 161, 162, 520, 1900, 500, 4500, 5353];
    const promises = [];

    for (let i = 1; i < 255; i++) {
        for (let port of commonPorts) {
            promises.push(udpCheck(`${subnet}.${i}`, port));
        }
    }

    const results = await Promise.all(promises);

    const grouped = {};

    results.filter(r => r.status === 'closed').forEach(r => {
        if (!grouped[r.host]) grouped[r.host] = [];
        grouped[r.host].push(`${r.port} (${r.status})`);
    });

    console.log("UDP sweep complete!");
    Object.entries(grouped).forEach(([host, ports]) => {
        console.log(`${host} → ${ports.join(', ')}`);
    });
}


async function findUdpPorts(host, commonPorts = [
    53, 67, 68, 69,
    123, 161, 162, 500,
    520, 1900, 4500, 5353,
    67, 68, 69, 514, 631
]) {
    console.log(`Starting udp sweep on host: ${host}.0/24`);

    const promises = [];

    for (let port of commonPorts) {
        promises.push(udpCheck(host, port));
    }

    const results = await Promise.all(promises);

    const grouped = {};

    results.filter(r => r.status === 'closed').forEach(r => {
        if (!grouped[r.host]) grouped[r.host] = [];
        grouped[r.host].push(`${r.port} (${r.status})`);
    });

    console.log("UDP sweep complete!");
    Object.entries(grouped).forEach(([host, ports]) => {
        console.log(`${host} → ${ports.join(', ')}`);
    });
}


module.exports = { udpSweep, findUdpPorts };
