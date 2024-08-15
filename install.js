const fs = require("fs")
if (process.platform === "linux") {
    fs.writeFileSync("/etc/systemd/system/js2ray.service",
        `[Unit]
Description="Js2ray"

[Service]
ExecStart=/usr/bin/node js2ray.js
WorkingDirectory=/root/js2ray
Restart=always
RestartSec=200ms
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=Js2ray
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target`
    )
}