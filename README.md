
# js2ray
The v2ray vmess protocol, based on nodejs javascript which you can use on cpanel hosts (that support nodejs) and servers


##  run
create file in `/root/js2ray/index.js` and write your script and then run with `systemctl enable js2ray;systemctl restart js2ray;` and your service will run for ever
##  debug
you can stop your service with `systemctl disable js2ray;systemctl stop js2ray;` and then run with `node /root/js2ray/index.js` for debugging
##  setup 
server side
```js
var js2ray = require("js2ray");
var config = {
    inbounds: [
        {
            protocol: "vmess",
            networks: [
                {
                    type: "http", // ws | tcp | http | httpAlt
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
                    security: "none",// auto || aes-128-gcm || chacha20-poly1305 || none || zero
                    alterId: 0,
                    // traffic: 130 * 1024 * 1024,
                    // ipCount: 10,
                }
            ],
        }
    ],
    debug: function (...e) {
        //console.log(...e)
    },
    storage: __dirname + "/app.json", 
}
js2ray.config(config).start()
```

client or bridge (tunnel) side

```js
var js2ray = require("js2ray");
var config = {
    inbounds: [
        {
            protocol: "vmess",
            networks: [
                {
                    type: "http", // ws | tcp | http | httpAlt
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
                    security: "none",// auto || aes-128-gcm || chacha20-poly1305 || none || zero
                    alterId: 0,
                    // traffic: 130 * 1024 * 1024,
                    // ipCount: 10,
                }
            ],
        }
    ],
    outbounds: [{
        tag: "outbound",
        protocol: "vmess",
        networks: [
            {
                type: "tcp", // ws | tcp | http | httpAlt
                address: "server.address",
                port: 1234
            }
        ],
        users: [
            {
                id: "b87cd5bc-71d1-e7c7-e031-24390995a198",
                security: "none",// auto || aes-128-gcm || chacha20-poly1305 || none || zero
                alterId: 0,
                // traffic: 130 * 1024 * 1024,
                // ipCount: 10,
            }
        ],
    }],
    storage: __dirname + "/app.json",
    debug: function (...e) {
        //console.log(...e)
    },
}
js2ray.config(config).start()
```
# api
you can empty `users: []` array and use `api` for remote controlling :

```js
var js2ray = require("js2ray");
var config = {
    inbounds: [
        {
            protocol: "vmess",
            networks: [
                {
                    type: "http", // ws | tcp | http | httpAlt
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
                    security: "none",// auto || aes-128-gcm || chacha20-poly1305 || none || zero
                    alterId: 0,
                    // traffic: 130 * 1024 * 1024,
                    // ipCount: 10,
                }
            ],
        }
    ],
    debug: function (...e) {
        //console.log(...e)
    },
    storage: __dirname + "/app.json", 
    api: {
        address: "0.0.0.0",
        port: 2050,
        post: {
            task: function () {
                return JSON.stringify({ rmx: Math.round(os.totalmem() / 1024 / 1024), ram: Math.round(os.freemem() / 1024 / 1024), net: Math.round(maxs) })
            },
            backup: function () {
                return fs.readFileSync(__dirname + "/app.json", "utf-8")
            }
        }
    }
}
js2ray.config(config).start()
```

# licence
 <p>
    <img width="32px" src="https://raw.githubusercontent.com/seezaara/RocketV2ray/main/doc/logo.png"><a href="https://www.youtube.com/@seezaara">created by seezaara</a>
</p> 
