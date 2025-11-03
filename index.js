const { Console } = require('node:console');
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

    const options = ['tcpSweepAll', 'Find common open tcp ports', 'Find common open udp ports', 'Find all open udp ports', 'Find all open tcp ports', 'udpSweepAll', 'tcpSweep (Common ports)', 'udpSweep (Common ports)', 'sendTcpProbes', 'Send TCP Probes and observer'];

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
                const targetIP = await askQuestion('Enter the target ip (e.g., 192.168.1.1): ', rl);
                if (selectedOption === 'Find common open tcp ports') await findTcpPorts(targetIP);
                if (selectedOption === 'Find common open udp ports') await findUdpPorts(targetIP);
                break;
            }

            case 'Find all open tcp ports':
            case 'Find all open udp ports': {
                const targetIP = await askQuestion('Enter the target ip (e.g., 192.168.1.1): ', rl);
                if (selectedOption === 'Find all open tcp ports') await findAllTcpPorts(targetIP);
                if (selectedOption === 'Find all open udp ports') await findAllUdpPorts(targetIP);
                break;
            }

            case 'tcpSweep (Common ports)':
            case 'udpSweep (Common ports)': {
                const subnet = await askQuestion('Enter the subnet (e.g., 192.168.1): ', rl);
                if (selectedOption === 'tcpSweep (Common ports)') await tcpSweep(subnet);
                if (selectedOption === 'udpSweep (Common ports)') await udpSweep(subnet);
                break;
            }

            case 'tcpSweepAll (Common ports)':
            case 'uspSweepAll (Common ports)': {
                Console.log('WARNING : tcpSweepAll is not a efficent option');
                Console.log('WARNING : Sending packets to all 65,536 ports , all devicess in subnet');
                if (selectedOption === 'tcpSweep (Common ports)') await tcpSweepAll(subnet);
                if (selectedOption === 'udpSweep (Common ports)') await udpSweepAll(subnet);
                break;
            }

            case 'sendTcpProbes': {
                const targetIP = await askQuestion('Enter the target IP: ', rl);
                const port = await askQuestion('Enter the port number: ', rl);
                await sendTcpProbes(targetIP, parseInt(port, 10));
                break;
            }

            case 'osDetection': { // This corresponds to tcpProbeDecode
                const yourIP = await askQuestion('Enter your source IP: ', rl);
                const targetIP = await askQuestion('Enter the target IP for OS detection: ', rl);
                await tcpProbeDecode(yourIP, targetIP);
                break;
            }

            case 'Send TCP Probes and observer': { // This corresponds to tcpProbeDecode
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

const ip = '10.59.216.214';
const subnet = '10.59.216';
const targetIP = '10.59.216.38';

// await udpSweep(subnet);
await tcpSweep(subnet);
await tcpProbeSweep(ip, targetIP);
// await tcpProbeDecode(ip, targetIP);
// await sendTcpProbes(targetIP, 53);
// await pinngSweep(subnet);
// await tacBanner(ip);
// await findAllTcpPorts(targetIP);
// await findTcpPorts(targetIP);
// await findUdpPorts(ip);
// await grabSingleBanner(targetIP, '2221');