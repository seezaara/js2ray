
const http = require("http")
const url = require('url');
var protocols
var post
var get
function init(data, in_protocols) {
    protocols = in_protocols
    post = data.post
    get = data.get
    http.createServer(server).listen(data.port, data.address)
}
async function server(req, res) {
    try {
        const queryData = url.parse(req.url, true);
        const key = queryData.pathname.substring(1)
        if (req.method == "POST") {
            var data = Buffer.alloc(0);
            req.on('data', function (chunk) {
                data = Buffer.concat([data, chunk])
            })
            req.on("close", async function () {
                try {
                    data = JSON.parse(data.toString() || "{}")
                    if (key == "") {
                        out = { ok: true, data: await api_open(data) }
                        res.end(JSON.stringify(out))
                    } else {
                        res.end(await post_open(key, data));
                    }
                } catch (error) {
                    log(error)
                }
            })

        }
        else if (req.method == "GET" && get) {
            res.end(await get_open(key, queryData.query));
        } else
            req.socket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
    } catch (error) {
        log(error)
    }
}
function api_open(req) {
    if (req.protocol && protocols[req.protocol] && typeof protocols[req.protocol].api[req.method] == "function") {
        if (req.attrs)
            return protocols[req.protocol].api[req.method](...req.attrs)
        else
            return protocols[req.protocol].api[req.method]()
    }
}
function post_open(key, req) {
    if (key in post && typeof post[key] == "function") {
        if (req)
            return post[key](req)
        else
            return post[key]({})
    }
}
function get_open(key, req) {
    if (key in get && typeof get[key] == "function") {
        if (req)
            return get[key](req)
        else
            return get[key]({})
    }
}
module.exports = { init }
