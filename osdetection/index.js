const NmapProbeOptions = require("../utils/tcp/tcp-option-probes");
const { tcp, ipv4 } = require('netcraft-js')
const { NmapProbeGenerator } = require('./options');
const raw = require("raw-socket");


const targetIP = "10.224.59.6";
const sourceIP = "10.224.59.214";

/*  
* Initialise new instance of the generator class
* Generate all probes
*/
let probesGenrator = new NmapProbeGenerator(
    sourceIP,
    targetIP,
    12345,
    53
)
const probes = probesGenrator.generateAllProbes();


/*
* Function to send tcp/ip packet via raw socket
*/
function sendProbes() {
    const socket = raw.createSocket({ protocol: raw.Protocol.TCP });

    socket.on("message", (buffer) => {

        const result = ipv4.DecodeHeader(buffer);
        const tcpResult = tcp.Decode(result.payload);
        if (result.srcIp === targetIP) {
            console.log("TCP/IP Probe Response from target:", result);
            console.log("TCP/IP Probe Response from target:", tcpResult);
        }
    });

    for (let probe of probes) {

        socket.send(probe.tcpHeader, 0, probe.tcpHeader.length, targetIP, (err) => {
            if (err) {
                console.error("Error occured :", err)
            }
        })
    }
}

sendProbes()