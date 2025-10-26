const { exec } = require("child_process");
const net = require("net");
function pingHost(host) {
    return new Promise((resolve) => {
        console.log(`Pinging ${host}...`);
        exec(`ping -c1 -w1 ${host}`, (error) => {
            if (!error) {
                resolve({ host, alive: true });
            } else {
                console.log(error, 'data')
                resolve({ host, alive: false });
            }
        });
    });
}


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
const commonPorts = [22, 53, 80, 443, 8080, 3128];


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


tcpSweep('10.236.104');
// pinngSweep('10.236.104');
