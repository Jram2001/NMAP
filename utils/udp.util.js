const dgram = require('dgram');

function udpCheck(host, port = 53, timeout = 2000) {
    return new Promise((resolve) => {
        const socket = dgram.createSocket('udp4');
        const message = Buffer.alloc(1);

        const timer = setTimeout(() => {
            resolve({ host, port, status: 'filtered' });
            socket.close();
        }, timeout);

        socket.send(message, 0, message.length, port, host, (err) => {
            if (err) {
                clearTimeout(timer);
                socket.close();
                resolve({ host, port, status: 'error' });
            }
        });

        socket.on('message', () => {
            clearTimeout(timer);
            socket.close();
            resolve({ host, port, status: 'open' });
        });

        socket.on('error', () => {
            clearTimeout(timer);
            socket.close();
            resolve({ host, port, status: 'closed' });
        });
    });
}

module.exports = { udpCheck };
