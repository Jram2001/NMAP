const { exec } = require("child_process");

function pingHost(host) {
    return new Promise((resolve) => {
        // console.log(`Pinging ${host}...`);
        exec(`ping -c1 -w1 ${host}`, (error, stdout, stderr) => {
            if (!error) {
                resolve({ host, alive: true });
            } else {
                resolve({ host, alive: false });
            }
        });
    });
}

module.exports = { pingHost }

