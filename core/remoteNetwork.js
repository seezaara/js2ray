
const net = require('net');
const WebSocket = require('ws')
const http = require('http')

function error(e) {
}

function remoteNetwork(networks) {
    const data = networks[Math.floor(Math.random() * networks.length)]
    try {
        if (!data.option) {
            data.option = {}
        }
        if (!data.option.path)
            data.option.path = '/'
        if (!data.type) {
            return function (address, port, option, remoteConnect, remoteMessage, remoteClose) {
                log("tcp client connected to " + address + " port " + port, 2)
                var remotesocket = new net.Socket();
                function close() {
                    if (remotesocket == null)
                        return
                    remotesocket.destroy()
                    remotesocket = null
                }
                remotesocket.setTimeout(10000);
                remotesocket.once('error', close);
                remotesocket.once('close', function () {
                    remoteClose && remoteClose()
                    remotesocket = null
                });
                if (remoteMessage)
                    remotesocket.on('data', remoteMessage);
                remotesocket.connect(port, address, remoteConnect);
                return remotesocket
            }
        } else if (data.type == "tcp") {
            return function (address, port, option, remoteConnect, remoteMessage, remoteClose) {
                log("tcp client connected to " + address + " port " + port, 2)
                var remotesocket = new net.Socket();
                function close() {
                    if (remotesocket == null)
                        return
                    remotesocket.destroy()
                    remotesocket = null
                }
                remotesocket.setTimeout(10000);
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
                if (!data.option.tls) {
                    var remotesocket = new WebSocket('ws://' + address + ':' + port + data.option.path, {
                        headers: data.option.headers
                    });
                } else {
                    var remotesocket = new WebSocket('wss://' + data.option.tls.serverName + port + data.option.path, {
                        ...data.option.tls,
                        lookup: (hostname, options, callback) => {
                            callback(null, [{ "address": address, "family": 4 }], 4);
                        },
                        headers: data.option.headers
                    });
                }
                function close() {
                    if (remotesocket == null)
                        return
                    remotesocket.close()
                    remotesocket = null
                }
                // =====================
                const timeout = setTimeout(close, 10000)
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
                remotesocket.setTimeout(10000);
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
        } else if (data.type === "xhttp") {
            const path = data.option.path.endsWith("/") ? data.option.path : data.option.path + "/";
            const mode = {
                "auto": 0,
                "packet-up": 1,
                "stream-up": 2,
                "stream-one": 3,
            }[data.option.mode || "auto"];
            const agent = http;
            const host = data.option.host;
            const headersBase = { "Host": host, ...(data.option.headers || {}) };
            const refererBase = "http://" + host + path;


            if (mode === 3) { // stream-one
                const streamHeaders = {
                    ...headersBase,
                    "Content-Type": "application/grpc",
                    "Transfer-Encoding": "chunked",
                    "Accept-Encoding": "gzip",
                    "Connection": "close",
                };

                return function (address, port, option, remoteConnect, remoteMessage, remoteClose) {
                    const headers = {
                        ...streamHeaders,
                        Referer: refererBase + buildReferer(""),
                    };

                    const req = agent.request({
                        method: "POST",
                        hostname: address,
                        port,
                        path: path,
                        headers,
                    }, (res) => {
                        remoteConnect();
                        res.socket.setTimeout(10000, res.socket.destroy.bind(res.socket));
                        res.on("data", remoteMessage);
                    });

                    req.on("error", remoteClose);
                    req.on("close", remoteClose);
                    req.write(""); // kick off connection

                    return {
                        message: req.write.bind(req),
                        close: req.end.bind(req)
                    };
                }
            } else if (mode === 1 || mode === 0) { // packet-up
                return function (address, port, option, remoteConnect, remoteMessage, remoteClose) {
                    const uuid = rand_id();
                    let seq = 0;

                    const headers = {
                        ...headersBase,
                        "Accept-Encoding": "gzip",
                        "Connection": "close",
                        Referer: refererBase + buildReferer(uuid)
                    };

                    const down = agent.get({
                        hostname: address,
                        port,
                        path: path + uuid,
                        headers,
                    }, (res) => {
                        remoteConnect();
                        res.socket.setTimeout(10000, res.socket.destroy.bind(res.socket));
                        res.on("data", remoteMessage);
                        res.on("end", remoteClose);
                    });


                    down.on("error", remoteClose);
                    down.on("close", remoteClose);

                    return {
                        message: buffer => {
                            const postHeaders = {
                                ...headersBase,
                                Referer: refererBase + buildReferer(uuid + "/" + seq)
                            };

                            const post = agent.request({
                                method: "POST",
                                hostname: address,
                                port,
                                path: path + uuid + "/" + (seq++),
                                headers: postHeaders
                            }, post => post.socket.setTimeout(10000, post.destroy.bind(post)));

                            post.on("error", error);
                            post.end(buffer);
                        },
                        close: down.destroy.bind(down)
                    };
                }
            }

            throw new Error("xhttp mode not supported");
        }
        else {
            throw ("network type '" + data.type + "' not supported")
        }
    } catch (error) {
        log(error)
    }
}
function buildReferer(extra) {
    return extra + "?x_padding=" + "X".repeat(Math.floor(Math.random() * 900 + 100));
}

function rand_id() { // min and max included 
    return Math.floor(Math.random() * (0xffffffff - 0x10000000) + 0x10000000).toString(16) + "-" +
        Math.floor(Math.random() * (0xffff - 0x1000) + 0x1000).toString(16) + "-" +
        Math.floor(Math.random() * (0xffff - 0x1000) + 0x1000).toString(16) + "-" +
        Math.floor(Math.random() * (0xffff - 0x1000) + 0x1000).toString(16) + "-" +
        Math.floor(Math.random() * (0xffffffffffff - 0x100000000000) + 0x100000000000).toString(16)
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


