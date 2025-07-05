
# js2ray

A Node.js implementation of the V2Ray VMess protocol (plus other protocols like SOCKS and Freedom). Deployable on cPanel Node.js hosts and dedicated servers.


## Install & Run

Install with:

```bash
npm i js2ray
````

Then create a file at `/root/js2ray/index.js`:

```js
var js2ray = require("js2ray");
// your config here
```

Run as a systemd service:

```bash
systemctl enable js2ray
systemctl restart js2ray
```

It will stay alive forever.


## Debug Mode

Stop the systemd service:

```bash
systemctl disable js2ray
systemctl stop js2ray
```

Then run manually for debugging:

```bash
node /root/js2ray/index.js
```


## Setup

### Server-side

```js
var js2ray = require("js2ray");

var config = {
    inbounds: [
        {
            protocol: "vmess",
            networks: [
                {
                    type: "http", // ws | tcp | http | xhttp
                    address: "0.0.0.0",
                    port: 80,
                    option: {
                        path: "/ws",
                        fake: "hello world"
                    },
                }
            ],
            users: [
                {
                    id: "b87cd5bc-71d1-e7c7-e031-24390995a198",
                    security: "none", // auto | aes-128-gcm | chacha20-poly1305 | none | zero
                    alterId: 0,
                }
            ],
        },
        {
            protocol: "socks",
            networks: [
                {
                    address: "0.0.0.0",
                    port: 1080
                }
            ],
            users: []
        }
    ],
    debug: function (...e) {
        // console.log(...e)
    },
    storage: __dirname + "/app.json",
}

js2ray.config(config).start();
```

---

### Client / Bridge Side (Tunnel)

```js
var js2ray = require("js2ray");

var config = {
    inbounds: [
        {
            protocol: "vmess",
            networks: [
                {
                    type: "http", // ws | tcp | http | xhttp
                    address: "0.0.0.0",
                    port: 80,
                    option: {
                        path: ["/", "/data"],
                        fake: "hello world"
                    },
                }
            ],
            users: [
                {
                    id: "b87cd5bc-71d1-e7c7-e031-24390995a155",
                    security: "none",
                    alterId: 0,
                }
            ],
        },
        {
            protocol: "socks",
            networks: [
                {
                    address: "0.0.0.0",
                    port: 1080
                }
            ],
            users: []
        }
    ],
    outbounds: [
        {
            tag: "outbound",
            protocol: "vmess",
            networks: [
                {
                    type: "tcp",
                    address: "server.address",
                    port: 1234
                }
            ],
            users: [
                {
                    id: "b87cd5bc-71d1-e7c7-e031-24390995a198",
                    security: "none",
                    alterId: 0,
                }
            ],
        }
    ],
    storage: __dirname + "/app.json",
    debug: function (...e) {
        // console.log(...e)
    },
}

js2ray.config(config).start();
```

---

### API-Enabled Server

You can leave `users: []` and instead manage them remotely via the `api` field.

```js
var js2ray = require("js2ray");
var fs = require("fs");
var os = require("os");

var config = {
    inbounds: [
        {
            protocol: "vmess",
            networks: [
                {
                    type: "http",
                    address: "0.0.0.0",
                    port: 80,
                    option: {
                        path: "/ws",
                        fake: "hello world"
                    },
                }
            ],
            users: []
        },
        {
            protocol: "socks",
            networks: [
                {
                    address: "0.0.0.0",
                    port: 1080
                }
            ],
            users: []
        }
    ],
    api: {
        address: "0.0.0.0",
        port: 2050,
        post: {
            task: function () {
                return JSON.stringify({
                    rmx: Math.round(os.totalmem() / 1024 / 1024),
                    ram: Math.round(os.freemem() / 1024 / 1024),
                    net: 0 // placeholder
                })
            },
            backup: function () {
                return fs.readFileSync(__dirname + "/app.json", "utf-8");
            }
        }
    },
    storage: __dirname + "/app.json",
    debug: function (...e) {
        // console.log(...e)
    },
}

js2ray.config(config).start();
```

---

## SOCKS Examples

### Minimal SOCKS Proxy with Freedom

```js
var js2ray = require("js2ray");

var config = {
    inbounds: [
        {
            protocol: "socks",
            networks: [
                {
                    address: "0.0.0.0",
                    port: 10805,
                }
            ],
            users: []
        }
    ],
    // if outbounds not defined, "freedom" is used by default
    storage: __dirname + "/app.json",
}

js2ray.config(config).start();
```

### SOCKS-to-SOCKS Tunnel (SOCKS Inbound + SOCKS Outbound)

```js
var js2ray = require("js2ray");

var config = {
    inbounds: [
        {
            protocol: "socks",
            networks: [
                {
                    address: "0.0.0.0",
                    port: 1080,
                }
            ],
            users: []
        }
    ],
    outbounds: [
        {
            protocol: "socks",
            networks: [
                {
                    address: "remote.socks.server",
                    port: 1080,
                }
            ],
            users: []
        }
    ],
    storage: __dirname + "/app.json",
}

js2ray.config(config).start();
```

---

## License

<p>
    <img width="32px" src="https://raw.githubusercontent.com/seezaara/RocketV2ray/main/doc/logo.png">
    <a href="https://www.youtube.com/@seezaara">seezaara YouTube</a><br>
    <img width="32px" src="https://raw.githubusercontent.com/seezaara/RocketV2ray/main/doc/logo.png">
    <a href="https://t.me/seezaara">seezaara Telegram</a>
</p>


