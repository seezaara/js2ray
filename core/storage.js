const fs = require("fs")
const events = require('events');
const event = new events.EventEmitter();
const out = {
    read,
    write,
    data: undefined, // read only,
    on: event.on.bind(event),
    location: undefined
}
setInterval(write, 30000);
function read(def = {}) {
    try {
        var usage = ""
        if (out.location && fs.existsSync(out.location)) {
            usage = fs.readFileSync(out.location);
        }
        if (usage == "") {
            usage = def
        } else {
            usage = JSON.parse(usage)
        }
        out.data = usage
        return usage;
    } catch (error) {
        Error("read file error: ")
        return {}
    }
}
function write(e) {
    if (out.location) {
        try {
            event.emit("write")
            fs.writeFileSync(out.location, JSON.stringify(out.data));
        } catch (error) {
            if (e !== true)
                write(true)
            console.log("write file error")
        }
    }
}

//=================================================================== before exit
process.stdin.resume();
function exitHandler(options, e) {
    if (options.error) console.error(e)
    if (options.cleanup) write();
    if (options.exit) process.exit();
}
process.on('exit', exitHandler.bind(null, { cleanup: true }));
process.on('SIGINT', exitHandler.bind(null, { exit: true }));
process.on('SIGUSR1', exitHandler.bind(null, { exit: true }));
process.on('SIGUSR2', exitHandler.bind(null, { exit: true }));
process.on('uncaughtException', exitHandler.bind(null, { exit: true, error: true }));
module.exports = out