const grabBanner = require('../utils/tcp.util').grabBanner;

async function tacBanner(host) {
    console.log(`Starting tcp sweep on subnet: ${host}.0/24`);

    const commonPorts = [22, 53, 80, 443, 8080, 3128];
    const promises = [];

    for (let port of commonPorts) {
        promises.push(grabBanner(host, port));
    }

    const results = await Promise.all(promises);

    results
        .filter(r => !!r.banner)
        .forEach(r => {
            console.log(r.banner)
        });

    console.log("tcp sweep complete!");
}

async function grabSingleBanner(host, port) {

    const result = await grabBanner(host, port);
    console.log(result)
    console.log('Banner grab complete')

}

module.exports = { tacBanner, grabSingleBanner };
