
const { WebSocketServer } = require('ws');
const net = require('net');
const http = require('http');
const https = require('http');

function onerror() {
}

function localNetwork(data, localProtocol) {
    try {
        const canIpCheck = data.ip != undefined
        const socketset = new Set();
        if (!data.option) {
            data.option = {}
        }
        if (!data.option.path)
            data.option.path = '/'
        if (!data.type)
            data.type = "tcp"
        if (typeof localProtocol == "object") {
            localProtocol.on("connection", function (localsocket) {
                if (canIpCheck && !checkIP(data.ip, localsocket.remoteAddress))
                    return localsocket.destroy();
                socketset.add(localsocket);
                localsocket.setTimeout(10000);
                localsocket.on("error", onerror)
                localsocket.on("close", function () {
                    socketset.delete(localsocket);
                })
            })
            return {
                stop: function () {
                    localProtocol.close()
                    for (const socket of socketset.values()) {
                        socket.destroy();
                    }
                },
                start: function () {
                    log("server is running on " + data.address + " port " + data.port, 1)
                    localProtocol.listen(data.port, data.address);
                }
            }
        } else if (data.type == "tcp") {
            var server = net.createServer(function (localsocket) {
                if (canIpCheck && !checkIP(data.ip, localsocket.remoteAddress))
                    return localsocket.destroy();

                socketset.add(localsocket);
                localsocket.on("close", function () {
                    socketset.delete(localsocket);
                })
                localsocket.localMessage = localsocket.write.bind(localsocket)
                localsocket.localClose = localsocket.destroy.bind(localsocket)
                const remoteProtocol = localProtocol(localsocket, localsocket.remoteAddress)
                localsocket.setTimeout(10000);
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
                if (data.option.tls) {
                    var server = https.createServer(data.option.tls, function (req, res) {
                        return res.end(data.option.fake)
                    })
                } else {
                    var server = http.createServer(function (req, res) {
                        return res.end(data.option.fake)
                    })
                }
            } else {
                if (data.option.tls)
                    var server = https.createServer(data.option.tls)
                else
                    var server = http.createServer()
            }
            function connected(ws, req) {
                const ip = req.headers['cf-connecting-ip'] || req.headers['fastly-client-ip'] || req.headers['x-forwarded-for']?.split(',')[0].trim() || ws._socket.remoteAddress;

                if (canIpCheck && !checkIP(data.ip, ip)) return ws.terminate();

                ws.localMessage = function (buffer) {
                    ws.send(buffer)
                }
                ws.localClose = function () {
                    ws.close()
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
            var server = net.createServer(function (localsocket) {
                if (canIpCheck && !checkIP(data.ip, localsocket.remoteAddress)) return localsocket.destroy();
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
                socketset.add(localsocket);
                localsocket.on("close", function () {
                    socketset.delete(localsocket);
                })
                localsocket.localMessage = localsocket.write.bind(localsocket)
                localsocket.localClose = localsocket.destroy.bind(localsocket)
                const remoteProtocol = localProtocol(localsocket, localsocket.remoteAddress)
                localsocket.setTimeout(10000);
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
        } else if (data.type === "xhttp") {
            const sessions = new Map(); // UUID -> { [SEQ]: Buffer, LS: socket }
            const path = data.option.path.endsWith("/") ? data.option.path : data.option.path + "/";
            const host = data.option.host;
            const mode = {
                "auto": 0,
                "packet-up": 1,
                "stream-up": 2,
                "stream-one": 3,
            }[data.option.mode || "auto"];

            const server = http.createServer((req, res) => {
                const ip = req.headers['cf-connecting-ip'] || req.headers['fastly-client-ip'] || req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;

                if (canIpCheck && !checkIP(data.ip, ip)) {
                    if (data.option.fake) {
                        return res.end(data.option.fake);
                    } else {
                        return req.socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
                    }
                }

                if (req.socket) req.socket.setTimeout(10000);

                if (host !== undefined &&
                    (typeof host === "string"
                        ? host !== req.headers["host"]
                        : !host.includes(req.headers["host"]))) {
                    return req.socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
                }

                let url = req.url;
                if (typeof path === "string" && url.startsWith(path)) {
                    url = url.slice(path.length);
                } else if (typeof path === "object") {
                    for (const p of path) {
                        if (url.startsWith(p)) {
                            url = url.slice(p.length);
                            break;
                        }
                    }
                } else if (data.option.fake) {
                    return res.end(data.option.fake);
                } else {
                    return req.socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
                }

                const [UUID, seqStr] = url.split("/");
                const SEQ = seqStr ? +seqStr : null;

                // --- POST (packet-up) ---
                if (req.method === "POST" && UUID && typeof SEQ === "number") {
                    if (mode !== 0 && mode !== 1) {
                        return req.socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
                    }

                    res.writeHead(200, {
                        "Access-Control-Allow-Methods": "GET, POST",
                        "Access-Control-Allow-Origin": "*",
                        "Content-Length": "0",
                    });
                    res.end();

                    let session = sessions.get(UUID);
                    if (!session) {
                        session = {};
                        sessions.set(UUID, session);
                    }

                    req.on("data", chunk => {
                        const s = session.LS;
                        if (s && s.rqr) {
                            if (SEQ === s.rqn) {
                                s.rqr.message(chunk);
                                s.rqn++;
                                while (s.rqh[s.rqn]) {
                                    s.rqr.message(s.rqh[s.rqn]);
                                    delete s.rqh[s.rqn++];
                                }
                            } else {
                                s.rqh[SEQ] = chunk;
                            }
                        } else {
                            session[SEQ] = chunk;
                        }
                    });
                }

                // --- GET (downlink) ---
                else if (req.method === "GET" && UUID) {
                    if (mode !== 0 && mode !== 1 && mode !== 2) {
                        return req.socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
                    }

                    const localsocket = req.socket;
                    if (!localsocket) return;

                    if (localsocket.rqr) {
                        localsocket.rqr.close()
                        localsocket.removeAllListeners("close");
                        localsocket.removeAllListeners("error");
                    }

                    socketset.add(localsocket);
                    localsocket.on("close", () => {
                        socketset.delete(localsocket);
                        sessions.delete(UUID);
                    });

                    res.writeHead(200, {
                        "Access-Control-Allow-Methods": "GET, POST",
                        "Access-Control-Allow-Origin": "*",
                        "Cache-Control": "no-store",
                        "Content-Type": "text/event-stream",
                        "X-Accel-Buffering": "no",
                        "Transfer-Encoding": "chunked",
                    });
                    res.flushHeaders();

                    localsocket.localMessage = res.write.bind(res);
                    localsocket.localClose = res.end.bind(res);
                    const remoteProtocol = localProtocol(localsocket, ip);

                    localsocket.on("close", remoteProtocol.close);
                    localsocket.on("error", remoteProtocol.close);
                    localsocket.rqr = remoteProtocol;
                    localsocket.rqn = 0;
                    localsocket.rqh = {};

                    let session = sessions.get(UUID);
                    if (!session) {
                        session = {};
                        sessions.set(UUID, session);
                    }
                    session.LS = localsocket;

                    for (const key in session) {
                        if (key === "LS") continue;
                        const seq = +key;
                        const chunk = session[key];
                        if (seq === localsocket.rqn) {
                            localsocket.rqr.message(chunk);
                            localsocket.rqn++;
                            while (localsocket.rqh[localsocket.rqn]) {
                                localsocket.rqr.message(localsocket.rqh[localsocket.rqn]);
                                delete localsocket.rqh[localsocket.rqn++];
                            }
                        } else {
                            localsocket.rqh[seq] = chunk;
                        }
                        delete session[key]; // clean used early buffer
                    }
                }

                // --- POST (stream-one / stream-up) ---
                else if (req.method === "POST") {
                    if (mode !== 0 && mode !== 2 && mode !== 3) {
                        return req.socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
                    }

                    const localsocket = req.socket;
                    if (!localsocket) return;

                    socketset.add(localsocket);
                    localsocket.on("close", () => socketset.delete(localsocket));

                    res.writeHead(200, {
                        "Access-Control-Allow-Methods": "GET, POST",
                        "Access-Control-Allow-Origin": "*",
                        "Cache-Control": "no-store",
                        "Content-Type": "text/event-stream",
                        "X-Accel-Buffering": "no",
                        "Transfer-Encoding": "chunked",
                    });
                    res.flushHeaders();

                    localsocket.localMessage = res.write.bind(res);
                    localsocket.localClose = res.end.bind(res);
                    const remoteProtocol = localProtocol(localsocket, ip);
                    localsocket.on("close", remoteProtocol.close);
                    localsocket.on("error", remoteProtocol.close);
                    req.on("data", remoteProtocol.message);
                }

                // --- Invalid ---
                else {
                    req.socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
                }
            });

            return {
                start: () => {
                    log("xhttp server running on " + data.address + ":" + data.port, 1);
                    server.listen(data.port, data.address);
                    server.setTimeout(3000);
                },
                stop: () => {
                    sessions.clear();
                    server.close();
                    server.closeAllConnections?.();
                    for (const socket of socketset.values()) {
                        socket.destroy();
                    }
                }
            };
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
function checkIP(ipList, ip) {
    if (!ipList.length === 0) return true;
    if (!ip) return false;
    return ipList.includes(ip) || ipList.includes(ip.replace(/^::ffff:/, ''));
}
function checkIP(ipList, ip) {
    if (ipList.length === 0) return true;
    if (!(ip && (ipList.includes(ip) || ipList.includes(ip.replace(/^::ffff:/, ''))))) {
        log("the client " + ip + " was not included in ip lists", 1);
        return false;
    }
    return true;
}
module.exports = function (data, localProtocol) {
    const out = []
    for (const i of data) {
        out.push(localNetwork(i, localProtocol))
    }
    return out;
}


