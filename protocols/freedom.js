

const net = require('net');
const dgram = require('dgram')

function freedom(address, port, cmd, onconnect, onmessage, onclose) {
    if (cmd == 2) {
        log("connected udp", address + ":" + port)
        var dgramsocket = dgram.createSocket('udp4');
        function close() {
            if (dgramsocket == null)
                return
            dgramsocket.close()
            dgramsocket = null
        }
        dgramsocket.on('error', close);
        dgramsocket.on('message', onmessage)
        // =====================
        const timeout = setTimeout(close, 30000)
        dgramsocket.on('close', function () {
            onclose()
            dgramsocket = null
            clearTimeout(timeout)
        });
        dgramsocket.on('message', clearTimeout.bind(null, timeout));
        // =====================
        dgramsocket.connect(port, address, onconnect);
        return {
            close,
            message: function (buffer) {
                if (dgramsocket == null)
                    return
                dgramsocket.send(buffer)
            },
        }
    } else {
        log("connected tcp", address + ":" + port)
        var remotesocket = new net.Socket();
        function close() {
            if (remotesocket == null)
                return
            remotesocket.destroy()
            remotesocket = null
        }
        remotesocket.on('close', function () {
            onclose()
            remotesocket = null
        }); 
        remotesocket.on('data', onmessage);
        remotesocket.on('error', close)
        remotesocket.setTimeout(30000)
        remotesocket.connect(port, address, onconnect);
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

 