const pinngSweep = require('./lib/ping').pinngSweep;
const tcpSweep = require('./lib/tcp').tcpSweep;
const udpSweep = require('./lib/udp').udpSweep;
const grabBanner = require('./utils/tcp.util').grabBanner;
const tacBanner = require('./lib/banner-grabbig').tacBanner;
const grabSingleBanner = require('./lib/banner-grabbig').grabSingleBanner;
const findTcpPorts = require('./lib/tcp').findTcpPorts;
const findUdpPorts = require('./lib/udp').findUdpPorts;
const findAllTcpPorts = require('./lib/tcp').findAllTcpPorts;
const tcpProbeSweep = require('./lib/tcp').tcpProbeSweep;
//UTIL
const sendTcpProbes = require('./utils/tcp.util').sendTcpProbes;

async function main() {

    const ip = '192.168.0.195';
    const subnet = '192.168.0';
    const targetIP = '192.168.0.1';

    // await udpSweep(subnet);
    // await tcpSweep(subnet);
    await tcpProbeSweep(ip, targetIP);
    // await sendTcpProbes(targetIP, 53);
    // await pinngSweep(subnet);
    // await tacBanner(ip);
    // await findAllTcpPorts(targetIP);
    // await findTcpPorts(targetIP);
    // await findUdpPorts(ip);
    // await grabSingleBanner(targetIP, '2221');
}

main();

