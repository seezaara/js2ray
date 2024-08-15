
const { WebSocketServer } = require('ws');
const net = require('net');
const http = require('http');

function onerror(e) {
    log(e)
}
function localNetwork(data, localProtocol) {
    try {
        const socketset = new Set();
        if (!data.option) {
            data.option = {}
        }
        if (!data.option.path)
            data.option.path = '/'
        if (data.type == "tcp") {
            var server = net.createServer(function (localsocket) {
                socketset.add(localsocket);
                localsocket.on("close", function () {
                    socketset.delete(localsocket);
                })
                localsocket.localMessage = localsocket.write.bind(localsocket)
                localsocket.localClose = localsocket.destroy.bind(localsocket)
                const remoteProtocol = localProtocol(localsocket, localsocket.remoteAddress)
                localsocket.setTimeout(30000);
                localsocket.on('data', remoteProtocol.message);
                localsocket.on("close", remoteProtocol.close)
                localsocket.on("error", remoteProtocol.close)
            });
            return {
                stop: function () {
                    server.close()
                    for (const socket of socketset.values()) {
                        socket.destroy();
                    }
                },
                start: function () {
                    log("tcp server is running on " + data.address + " port " + data.port, 1)
                    server.listen(data.port, data.address);
                }
            }
        } else if (data.type == "ws") {
            const wss = new WebSocketServer({ noServer: true });
            if (data.option.fake) {
                var server = http.createServer(function (req, res) {
                    return res.end(data.option.fake)
                })
            } else {
                var server = http.createServer()
            }
            function connected(ws, req) {
                ws.localMessage = function (buffer) {
                    ws.send(buffer)
                }
                ws.localClose = function () {
                    ws.close()
                }
                var ip
                if (req.headers['x-forwarded-for']) {
                    ip = req.headers['x-forwarded-for'].split(',')[0].trim();
                } else {
                    ip = ws._socket.remoteAddress
                }
                const remoteProtocol = localProtocol(ws, ip)
                ws.on("close", function () { remoteProtocol.close() })
                ws.on("error", function () { remoteProtocol.close() })
                ws.on('message', function (buffer) { remoteProtocol.message(buffer) });
            }
            server.on('upgrade', function (request, socket, head) {
                if (typeof data.option.path == "string" ? request.url == data.option.path : data.option.path.includes(request.url)) {
                    wss.handleUpgrade(request, socket, head, connected);
                } else
                    socket.destroy();
            });
            return {
                stop: function () {
                    server.close()
                    server.closeAllConnections()
                    for (const socket of wss.clients) {
                        socket.terminate();
                    }
                },
                start: function () {
                    log("ws server is running on " + data.address + " port " + data.port, 1)
                    server.listen(data.port, data.address);
                }
            }
        } else if (data.type == "http") {
            const headers = create_header("HTTP/1.1 200 OK", data.option.headers, {
                "Connection": "keep-alive",
                "Content-Type": "text/html",
                "Pragma": "no-cache",
                "Transfer-Encoding": "chunked",
                "Date": new Date().toLocaleString('en-GB', {
                    timeZone: 'UTC',
                    hour12: false,
                    weekday: 'short',
                    year: 'numeric',
                    month: 'short',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                }).replace(/(?:(\d),)/, '$1') + ' GMT'
            })
            var server = net.createServer(function (localsocket) {
                socketset.add(localsocket);
                localsocket.on("close", function () {
                    socketset.delete(localsocket);
                })
                localsocket.localMessage = localsocket.write.bind(localsocket)
                localsocket.localClose = localsocket.destroy.bind(localsocket)
                const remoteProtocol = localProtocol(localsocket, localsocket.remoteAddress)
                localsocket.setTimeout(30000);
                localsocket.on("error", remoteProtocol.close)
                localsocket.on("close", remoteProtocol.close)
                localsocket.on('data', function (buffer) {
                    var indhttp = buffer.indexOf('\r\n\r\n')
                    if (indhttp != -1) {
                        if (buffer.subarray(0, 3) == "GET" || buffer.subarray(0, 4) == "POST") {
                            var path = buffer.subarray(buffer.indexOf(' ') + 1, buffer.indexOf(' HTTP')).toString()
                            if (typeof data.option.path == "string" ? path == data.option.path : data.option.path.includes(path)) {
                                localsocket.rh = true
                                this.write(headers)
                                if (buffer.length != indhttp + 4) {
                                    return remoteProtocol.message.call(this, buffer.subarray(indhttp + 4))
                                } else {
                                    return
                                }
                            } else if (data.option.fake) {
                                this.write(headers)
                                this.write(data.option.fake)
                                return this.end()
                            }
                        }
                    } else if (localsocket.rh == true) {
                        remoteProtocol.message.call(this, buffer)
                    }
                });
            });
            return {
                stop: function () {
                    server.close()
                    for (const socket of socketset.values()) {
                        socket.destroy();
                    }
                },
                start: function () {
                    log("http server is running on " + data.address + " port " + data.port, 1)
                    server.listen(data.port, data.address);
                }
            }
        } else if (data.type == "httpAlt") {
            const headers = create_header("HTTP/1.1 200 OK", data.option.headers, {
                "Connection": "keep-alive",
                "Content-Type": "text/html",
                "Pragma": "no-cache",
                "Transfer-Encoding": "chunked",
                "Date": new Date().toLocaleString('en-GB', {
                    timeZone: 'UTC',
                    hour12: false,
                    weekday: 'short',
                    year: 'numeric',
                    month: 'short',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                }).replace(/(?:(\d),)/, '$1') + ' GMT'
            })
            var server = http.createServer()
            server.on('connection', function (localsocket) {
                socketset.add(localsocket);
                localsocket.on("close", function () {
                    socketset.delete(localsocket);
                })
                localsocket.localMessage = localsocket.write.bind(localsocket)
                localsocket.localClose = localsocket.destroy.bind(localsocket)
                const remoteProtocol = localProtocol(localsocket, localsocket.remoteAddress)
                localsocket.setTimeout(30000);
                localsocket.on("error", remoteProtocol.close)
                localsocket.on("close", remoteProtocol.close)
                localsocket.on('data', function (buffer) {
                    var indhttp = buffer.indexOf('\r\n\r\n')
                    if (indhttp != -1 && (buffer.subarray(0, 3) == "GET" || buffer.subarray(0, 4) == "POST")) {
                        var path = buffer.subarray(buffer.indexOf(' ') + 1, buffer.indexOf(' HTTP')).toString()
                        if (typeof data.option.path == "string" ? path == data.option.path : data.option.path.includes(path)) {
                            this.write(headers)
                            if (buffer.length != indhttp + 4) {
                                return remoteProtocol.message.call(this, buffer.subarray(indhttp + 4))
                            } else {
                                return
                            }
                        } else if (data.option.fake) {
                            this.write(headers)
                            this.write(data.option.fake)
                            return this.end()
                        }
                    } else {
                        remoteProtocol.message.call(this, buffer)
                    }
                });
            })
            return {
                stop: function () {
                    server.close()
                    server.closeAllConnections()
                    for (const socket of socketset.values()) {
                        socket.destroy();
                    }
                },
                start: function () {
                    log("httpAlt server is running on " + data.address + " port " + data.port, 1)
                    server.listen(data.port, data.address);
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
module.exports = function (data, localProtocol) {
    const out = []
    for (const i of data) {
        out.push(localNetwork(i, localProtocol))
    }
    return out;
}