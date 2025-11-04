const readline = require('node:readline');
const tcpProbeSweep = require('./lib/tcp').tcpProbeSweep;
const findAllTcpPorts = require('./lib/tcp').findAllTcpPorts;
const findTcpPorts = require('./lib/tcp').findTcpPorts;
const pinngSweep = require('./lib/ping').pinngSweep;
const tcpSweep = require('./lib/tcp').tcpSweep;
const tcpSweepAll = require('./lib/tcp').tcpSweepAll;
const udpSweepAll = require('./lib/udp').udpSweepAll;
const findUdpPorts = require('./lib/udp').findUdpPorts;
const findAllUdpPorts = require('./lib/udp').findAllUdpPorts;
const udpSweep = require('./lib/udp').udpSweep;
const tcpProbeDecode = require('./lib/tcp').tcpProbeDecode;
const sendTcpProbes = require('./utils/tcp.util').sendTcpProbes;


// Helper function to ask questions asynchronously
function askQuestion(query, rl) {
    return new Promise(resolve => rl.question(query, resolve));
}

async function main() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        terminal: false
    });

    const options = ['Find common open tcp ports', 'Find common open udp ports', 'Find all open udp ports', 'Find all open tcp ports', 'tcpSweepAll', 'udpSweepAll', 'tcpSweep (Common ports)', 'udpSweep (Common ports)', 'sendTcpProbes', 'Send TCP Probes and observer'];

    console.log('Please choose a scan to perform:');
    options.forEach((option, index) => {
        console.log(`${index + 1}. ${option}`);
    });
    console.log(`${options.length + 1}. Exit`);

    const choiceStr = await askQuestion('Enter the number of your choice: ', rl);
    const choice = parseInt(choiceStr, 10);

    if (choice === options.length + 1) {
        console.log('Exiting...');
        rl.close();
        return;
    }

    if (!(choice > 0 && choice <= options.length)) {
        console.log('Invalid choice. Please run the script again.');
        rl.close();
        return;
    }

    const selectedOption = options[choice - 1];
    console.log(`You selected: ${selectedOption}`);

    // Now, conditionally ask for the required inputs
    try {
        switch (selectedOption) {

            case 'Find common open tcp ports':
            case 'Find common open udp ports': {
                if (selectedOption === 'Find common open tcp ports') {
                    console.log('\n╔════════════════════════════════════════╗');
                    console.log('║     🔍 TCP PORT SCANNER (COMMON)       ║');
                    console.log('║                                        ║');
                    console.log('║   ┌─┐  ┌─┐  ┌─┐  ┌─┐  ┌─┐  ┌─┐  ┌─┐    ║');
                    console.log('║   │▓│  │▓│  │▓│  │▓│  │▓│  │▓│  │▓│    ║');
                    console.log('║   └─┘  └─┘  └─┘  └─┘  └─┘  └─┘  └─┘    ║');
                    console.log('║                                        ║');
                    console.log('╚════════════════════════════════════════╝\n');
                } else {
                    console.log('\n╔═════════════════════════════════════════╗');
                    console.log('║     🔍 UDP PORT SCANNER (COMMON)        ║');
                    console.log('║  ◉───◉───◉───◉───◉───◉───◉───◉───◉      ║');
                    console.log('║   //   //   //   //   //   //   //      ║');
                    console.log('║    UDP PACKETS FLYING...                ║');
                    console.log('╚═════════════════════════════════════════╝\n');
                }
                const targetIP = await askQuestion('Enter the target ip (e.g., 192.168.1.1): ', rl);
                if (selectedOption === 'Find common open tcp ports') await findTcpPorts(targetIP);
                if (selectedOption === 'Find common open udp ports') await findUdpPorts(targetIP);
                break;
            }

            case 'Find all open tcp ports':
            case 'Find all open udp ports': {
                if (selectedOption === 'Find all open tcp ports') {
                    console.log('\n╔════════════════════════════════════════╗');
                    console.log('║    ⚡ FULL TCP PORT SCAN (1-65535)     ║');
                    console.log('║                                        ║');
                    console.log('║   ████████████████████████████████     ║');
                    console.log('║   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓     ║');
                    console.log('║   ALL 65,536 PORTS SCANNING...         ║');
                    console.log('╚════════════════════════════════════════╝\n');
                } else {
                    console.log('\n╔════════════════════════════════════════╗');
                    console.log('║    ⚡ FULL UDP PORT SCAN (1-65535)    ║');
                    console.log('║                                        ║');
                    console.log('║   ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈    ║');
                    console.log('║   FLOODING ALL UDP PORTS...           ║');
                    console.log('╚════════════════════════════════════════╝\n');
                }
                const targetIP = await askQuestion('Enter the target ip (e.g., 192.168.1.1): ', rl);
                if (selectedOption === 'Find all open tcp ports') await findAllTcpPorts(targetIP);
                if (selectedOption === 'Find all open udp ports') await findAllUdpPorts(targetIP);
                break;
            }

            case 'tcpSweep (Common ports)':
            case 'udpSweep (Common ports)': {
                if (selectedOption === 'tcpSweep (Common ports)') {
                    console.log('\n╔════════════════════════════════════════╗');
                    console.log('║       🌐 TCP NETWORK SWEEP             ║');
                    console.log('║                                        ║');
                    console.log('║    [PC] → [PC] → [PC] → [PC]           ║');
                    console.log('║     ↓      ↓      ↓      ↓             ║');
                    console.log('║    SCANNING SUBNET...                  ║');
                    console.log('╚════════════════════════════════════════╝\n');
                } else {
                    console.log('\n╔═══════════════════════════════════════╗');
                    console.log('║       🌐 UDP NETWORK SWEEP             ║');
                    console.log('║                                        ║');
                    console.log('║    •→ •→ •→ •→ •→ •→ •→ •→ •→          ║');
                    console.log('║    BROADCASTING SUBNET...              ║');
                    console.log('╚════════════════════════════════════════╝\n');
                }
                const subnet = await askQuestion('Enter the subnet (e.g., 192.168.1): ', rl);
                if (selectedOption === 'tcpSweep (Common ports)') await tcpSweep(subnet);
                if (selectedOption === 'udpSweep (Common ports)') await udpSweep(subnet);
                break;
            }

            case 'tcpSweepAll':
            case 'udpSweepAll': {
                console.log('\n╔════════════════════════════════════════╗');
                console.log('║     ⚠️  WARNING: AGGRESSIVE SCAN ⚠️    ║');
                console.log('║                                        ║');
                console.log('║   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    ║');
                console.log('║   █ ALL 65,536 PORTS                  ║');
                console.log('║   █ ENTIRE SUBNET                     ║');
                console.log('║   █ HIGH NETWORK LOAD                 ║');
                console.log('║                                        ║');
                console.log('║   This may take considerable time...  ║');
                console.log('╚════════════════════════════════════════╝\n');

                console.log('WARNING: tcpSweepAll is not an efficient option');
                console.log('WARNING: Sending packets to all 65,536 ports, all devices in subnet\n');

                const subnet = await askQuestion('Enter the subnet (e.g., 192.168.1): ', rl);
                if (selectedOption === 'tcpSweepAll') await tcpSweepAll(subnet);
                if (selectedOption === 'udpSweepAll') await udpSweepAll(subnet);
                break;
            }

            case 'sendTcpProbes': {
                console.log('\n╔════════════════════════════════════════╗');
                console.log('║      🎯 TCP PROBE TRANSMITTER         ║');
                console.log('║                                        ║');
                console.log('║         ┌────┐                        ║');
                console.log('║    ════>│PORT│<════                   ║');
                console.log('║         └────┘                        ║');
                console.log('║   Sending specialized TCP probes...   ║');
                console.log('╚════════════════════════════════════════╝\n');

                const targetIP = await askQuestion('Enter the target IP: ', rl);
                const port = await askQuestion('Enter the port number: ', rl);
                await sendTcpProbes(targetIP, parseInt(port, 10));
                break;
            }

            case 'osDetection': {
                console.log('\n╔════════════════════════════════════════╗');
                console.log('║     🔬 OS FINGERPRINT ANALYZER        ║');
                console.log('║                                        ║');
                console.log('║       ╔═══════════════╗               ║');
                console.log('║       ║ ? ? ? ? ? ? ? ║               ║');
                console.log('║       ║  ANALYZING... ║               ║');
                console.log('║       ╚═══════════════╝               ║');
                console.log('║   Detecting operating system...       ║');
                console.log('╚════════════════════════════════════════╝\n');

                const yourIP = await askQuestion('Enter your source IP: ', rl);
                const targetIP = await askQuestion('Enter the target IP for OS detection: ', rl);
                await tcpProbeDecode(yourIP, targetIP);
                break;
            }

            case 'Send TCP Probes and observer': {
                console.log('\n╔════════════════════════════════════════╗');
                console.log('║    📡 TCP PROBE & OBSERVER MODE       ║');
                console.log('║                                        ║');
                console.log('║    ┌──────┐         ┌──────┐          ║');
                console.log('║    │PROBE │ ══════> │TARGET│          ║');
                console.log('║    └──────┘         └──────┘          ║');
                console.log('║         ↓              ↓              ║');
                console.log('║    [MONITORING RESPONSES]             ║');
                console.log('╚════════════════════════════════════════╝\n');

                const yourIP = await askQuestion('Enter your source IP: ', rl);
                const targetIP = await askQuestion('Enter the target IP: ', rl);
                await tcpProbeDecode(yourIP, targetIP);
                break;
            }
        }
    } catch (error) {
        console.error('An error occurred during the operation:', error);
    } finally {
        rl.close();
    }
}

main();

// const ip = '10.59.216.214';
// const subnet = '10.59.216';
// const targetIP = '10.59.216.38';

// await udpSweep(subnet);
// await tcpSweep(subnet);
// await tcpProbeSweep(ip, targetIP);
// await tcpProbeDecode(ip, targetIP);
// await sendTcpProbes(targetIP, 53);
// await pinngSweep(subnet);
// await tacBanner(ip);
// await findAllTcpPorts(targetIP);
// await findTcpPorts(targetIP);
// await findUdpPorts(ip);
// await grabSingleBanner(targetIP, '2221');