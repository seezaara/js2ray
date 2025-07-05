"use strict";
const protocols = {}
protocols.vmess = require('./protocols/vmess')
protocols.socks = require('./protocols/socks');
const freedom = require('./protocols/freedom');
// const bridge = require('./protocols/bridge');
const localNetwork = require('./core/localNetwork');
const remoteNetwork = require('./core/remoteNetwork');
const event = require('./core/event');
const storage = require('./core/storage');
const api = require('./core/api');


// function initbridge(data) {
//     if (!data.outbound)
//         throw ("outbound is not defined (in bridge mode outbound must be defined)")
//     if (data.outbound.protocol)
//         throw ("do not use outbound protocol in bridge mode")
//     var remoteProtocol = bridge(data.outbound.networks, remoteNetwork(data.outbound.networks))
//     for (const i of data.inbounds) {
//         if (i.protocol)
//             throw ("do not use inbound protocol in bridge mode")
//         localNetwork(i.networks, remoteProtocol)
//     }
// }
function remoteRouting(array_outbounds = [], routing) {
    if (array_outbounds.length == 0)
        array_outbounds[0] = {
            protocol: 'freedom'
        }
    const outbounds = {}
    for (const i in array_outbounds) {
        const outbound = array_outbounds[i]
        if (!outbound.protocol || outbound.protocol == "freedom") {
            outbounds[outbound.tag || i] = freedom
        } else {
            outbounds[outbound.tag || i] = protocols[outbound.protocol].client(outbound, remoteNetwork(outbound.networks))
        }
    }
    if (typeof routing == "function") {
        return function (address, port, cmd, onconnect, onmessage, onclose) {
            var remoteTag = routing(address, port, cmd, this.tag /* tag */)
            if (remoteTag === true)
                return Object.values(outbounds)[0](address, port, cmd, onconnect, onmessage, onclose)
            else if (outbounds[remoteTag]) {
                return outbounds[remoteTag](address, port, cmd, onconnect, onmessage, onclose)
            } else {
                onclose()
            }
        }
    } else
        return Object.values(outbounds)[0]
}

function config(data) {
    storage.location = data.storage
    storage.read()
    global.log = function (...mess) {
        if (data.debug) {
            data.debug(...mess)
        }
        return false;
    }
    if (data.api)
        api.init(data.api, protocols)
    //===========================
    // if (data.bridge == true) {
    //     return bridge(data)
    // }
    const remoteProtocol = remoteRouting(data.outbounds, data.routing)
    const locals = []
    for (const i of data.inbounds) {
        if (!i.protocol || !(i.protocol in protocols))
            throw ("inbound protocol is not defined")
        const local = localNetwork(i.networks, protocols[i.protocol].server(i, remoteProtocol.bind(i)))
        locals.push(...local)
    }
    return {
        stop: function () {
            for (var i of locals)
                i.stop()
        },
        start: function () {
            for (var i of locals) {
                if (!i)
                    throw ("inbound network is not defined")
                i.start()
            }
        }
    }
}


module.exports = {
    config,
    on: event.on,
    protocols
}

