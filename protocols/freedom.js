

const net = require('net');
const dgram = require('dgram'),
    utils = require('../core/utils')

function freedom(address, port, cmd, onconnect, onmessage, onclose) {
    if (cmd == 3) {
        log("connected udp bind", address + ":" + port)
        return utils.UDPBind(onconnect, onmessage, onclose)
    } else if (cmd == 2) {
        // =====================
        if (typeof onmessage == "object") {
            const pipeSocket = onmessage
            onmessage = pipeSocket.write.bind(pipeSocket)
            onclose = pipeSocket.destroy.bind(pipeSocket)
            pipeSocket.on("error", close)
            pipeSocket.on("close", close)
            pipeSocket.on("data", message)
        }

        log("connected udp", address + ":" + port)
        var dgramsocket
        if (net.isIPv4(address)) {
            dgramsocket = dgram.createSocket('udp4');
        } else if (net.isIPv6(address)) {
            dgramsocket = dgram.createSocket('udp6');
        } else {
            onclose()
        }

        function close() {
            if (dgramsocket == null)
                return
            dgramsocket.close()
            dgramsocket = null
        }
        function message(buffer) {
            if (dgramsocket == null)
                return
            dgramsocket.send(buffer)
        }
        if (dgramsocket) {
            dgramsocket.on('error', close);
            dgramsocket.on('message', onmessage)
            // =====================
            const timeout = setTimeout(close, 10000)
            dgramsocket.on('close', function () {
                onclose()
                dgramsocket = null
                clearTimeout(timeout)
            });
            dgramsocket.on('message', clearTimeout.bind(null, timeout));
            // =====================
            if (port && port > 0 && port < 65536 && dgramsocket)
                dgramsocket.connect(port, address, onconnect);
            else
                onclose()
        }
        return {
            close,
            message,
        }
    } else if (cmd == 1) {
        log("connected tcp", address + ":" + port)
        var remotesocket = new net.Socket();
        function close() {
            if (remotesocket == null)
                return
            remotesocket.destroy()
            remotesocket = null
        }
        // =====================
        if (typeof onmessage == "object") {
            onmessage.pipe(remotesocket);
            remotesocket.pipe(onmessage);
        } else {
            remotesocket.on('close', function () {
                onclose()
                remotesocket = null
            });
            remotesocket.on('data', onmessage);
        }
        remotesocket.on('error', close)
        // =====================
        remotesocket.setTimeout(10000)
        if (port > 0 && port < 65536)
            remotesocket.connect(port, address, onconnect);
        else
            onclose()
        return {
            close,
            message: function (buffer) {
                if (remotesocket == null)
                    return
                remotesocket.write(buffer)
            }
        }
    }
}
module.exports = freedom

