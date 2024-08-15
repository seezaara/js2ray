
const net = require('net');
const WebSocket = require('ws')

function error(e) {
    log(e)
}

function remoteNetwork(networks) {
    const data = networks[Math.floor(Math.random() * networks.length)]
    try {
        if (!data.option) {
            data.option = {}
        }
        if (!data.option.path)
            data.option.path = '/'
        if (data.type == "tcp") {
            return function (address, port, option, remoteConnect, remoteMessage, remoteClose) {
                log("tcp client connected to " + address + " port " + port, 2)
                var remotesocket = new net.Socket();
                function close() {
                    if (remotesocket == null)
                        return
                    remotesocket.destroy()
                    remotesocket = null
                }
                remotesocket.setTimeout(30000);
                remotesocket.on('error', close);
                remotesocket.on('close', function () {
                    remoteClose()
                    remotesocket = null
                });
                remotesocket.on('data', remoteMessage);
                remotesocket.connect(port, address, remoteConnect);
                return {
                    message: function (buffer) {
                        if (remotesocket == null)
                            return
                        remotesocket.write(buffer)
                    },
                    close
                }
            }
        } else if (data.type == "ws") {
            return function (address, port, option, remoteConnect, remoteMessage, remoteClose) {
                log("ws client connected to " + address + " port " + port, 2)
                var remotesocket = new WebSocket('ws://' + address + ':' + port + data.option.path, {
                    headers: data.option.headers
                });
                function close() {
                    if (remotesocket == null)
                        return
                    remotesocket.close()
                    remotesocket = null
                }
                // =====================
                const timeout = setTimeout(close, 30000)
                remotesocket.on('error', close);
                remotesocket.on('close', function () {
                    remoteClose()
                    clearTimeout(timeout)
                    remotesocket = null
                });
                remotesocket.on('message', function (buffer) {
                    remoteMessage(buffer)
                    clearTimeout(timeout)
                });
                // =====================
                remotesocket.on('open', remoteConnect);
                return {
                    message: function (buffer) {
                        if (remotesocket == null)
                            return
                        remotesocket.send(buffer)
                    },
                    close
                }
            }
        } else if (data.type == "http") {
            const headers = create_header("GET " + data.option.path + " HTTP/1.1", data.option.headers, {
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Pragma": "no-cache",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            })
            return function (address, port, option, remoteConnect, remoteMessage, remoteClose) {
                log("http client connected to " + address + " port " + port, 2)
                var remotesocket = new net.Socket();
                function close() {
                    if (remotesocket == null)
                        return
                    remotesocket.destroy()
                    remotesocket = null
                }
                remotesocket.setTimeout(30000);
                remotesocket.on('error', close);
                remotesocket.on('close', function () {
                    remoteClose()
                    remotesocket = null
                });
                remotesocket.on('data', function (buffer) {
                    var indhttp = buffer.indexOf('\r\n\r\n')
                    if (indhttp != -1 && (buffer.subarray(0, 5) == "HTTP/")) {
                        if (buffer.length != indhttp + 4) {
                            return remoteMessage(buffer.subarray(indhttp + 4))
                        } else {
                            return
                        }
                    } else {
                        remoteMessage(buffer)
                    }
                });

                remotesocket.connect(port, address, remoteConnect);
                return {
                    message: function (buffer) {
                        if (remotesocket == null)
                            return
                        if (remotesocket.rh != true) {
                            remotesocket.write(headers)
                            remotesocket.rh = true
                        }
                        remotesocket.write(buffer)
                    },
                    close
                }
            }
        } else {
            throw ("network type '" + data.type + "' not supported")
        }
    } catch (error) {
        log(error)
    }
}

function create_header(pre, obj = {}, defaults) {
    var out = pre + "\r\n"
    if (defaults)
        obj = { ...defaults, ...obj }
    for (const i in obj) {
        if (obj[i])
            out += pascalCase(i) + ": " + obj[i] + "\r\n"
    }
    return out + "\r\n"
}
function pascalCase(str) {
    return str.replace(/\w+/g, function (w) { return w[0].toUpperCase() + w.slice(1).toLowerCase(); })
}
module.exports = remoteNetwork


