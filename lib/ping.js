const pingHost = require('../utils/ping.util').pingHost;

async function pinngSweep(subnet) {
    console.log(`Starting ping sweep on subnet: ${subnet}.0/24`);

    const promises = [];
    for (let i = 1; i < 255; i++) {
        promises.push(pingHost(`${subnet}.${i}`));
    }

    const results = await Promise.all(promises);

    const activeHost = results.filter(data => data.alive).map(data => data.host);

    console.log("Ping sweep complete!");
    console.log(`Alive hosts (${activeHost.length} found):`);
    activeHost.forEach(host => console.log(` - ${host}`));
}

module.exports = { pinngSweep };
