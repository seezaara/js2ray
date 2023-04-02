
const net = require('net');
const dgram = require('dgram')
function error() { }
function connect(host, port, cmd, connect, data) {
    log("connected ", cmd == 1 ? "tcp" : "udp", host + ":" + port)
    if (cmd == 2) {
        var dgramsocket = dgram.createSocket('udp4');
        dgramsocket.connect(port, host, connect);
        dgramsocket.on('error', error);
        dgramsocket.on('message', data)
        dgramsocket.outbound = dgramsocket.send.bind(dgramsocket)

    } else {
        var remotesocket = new net.Socket();
        remotesocket.setTimeout(60000)
        remotesocket.connect(port, host, connect);
        remotesocket.on('error', error);
        remotesocket.on('data', data);
        remotesocket.outbound = remotesocket.write.bind(remotesocket)
    }
};


// var http = require("http")

// const https = require(`https`);
// const fs = require(`fs`);

// http.createServer(mmd).listen(80, "127.0.0.1")
// https.createServer({
//     key: fs.readFileSync(`D:/trojan/key.pem`),
//     cert: fs.readFileSync(`D:/trojan/cert.pem`)
// }, mmd).listen(443, "127.0.0.1");

// function mmd(req, res) {
//     res.writeHead(200, {
//         'Server': "nginx",
//         'ETag': "5f3bb508-658",
//         'Cache-Control': "no-cache",
//         'MiCGI-Host': "router.miwifi.com",
//         'MiCGI-Http-Host': "router.miwifi.com",
//         'Content-Type': "text/html;charset=utf-8",
//     });
//     res.end('<body style=background:#1782dd;font-family:system-ui><div id=doc><div id=ft style=color:#8cb9f0;text-align:center;padding-top:70px;direction:rtl;font-size:90px><p>ترافیک vpn شما تمام شده<p></div></div>');
// }

module.exports = {
    connect
}