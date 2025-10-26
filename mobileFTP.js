const net = require('net')

const client = new net.createConnection({ host: '10.156.25.118', port: '2121' }, (connection) => {
    client.write("USER anonymous\r\n");
    client.write("PASS 12345\r\n");
    client.write("QUIT\r\n");
})

client.on('data', (data) => {
    console.log('Server says', data, data.toString());
})


client.on('end', () => {
    console.log('Disconnected from server');
});