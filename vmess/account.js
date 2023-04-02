
const crypto = require('crypto');
const fs = require('fs');
const { setInterval } = require('timers');
const consts = require("./consts")
function New() {
    return crypto.randomBytes(16)
}

function tostring(bytes) {
    var byteGroups = [8, 4, 4, 4, 12]
    var result = bytes.slice(0, byteGroups[0] / 2).toString('hex')
    var start = byteGroups[0] / 2
    for (var i = 1; i < byteGroups.length; i++) {
        var nBytes = byteGroups[i] / 2
        result += "-"
        result += bytes.slice(start, start + nBytes).toString('hex')
        start += nBytes
    }
    return result
}

function ParseString(id) {
    return (Buffer.from(id.replace(/-/g, ''), 'hex'));
}


function NewID(UUID) {
    return {
        UUID,
        cmdKey: (crypto.createHash('md5')
            .update(UUID)
            .update(Buffer.from("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
            .digest())
    }
}
function nextID(u) {
    var hash = crypto.createHash('md5')
        .update(u)
        .update(Buffer.from("16167dc8-16b6-4e6d-b8bb-65dd68113a81"))
    while (true) {
        var newid = hash.digest()
        if (!equals(newid, u)) {
            return (newid);
        }
        hash.update(Buffer.from("533eff8a-4113-4b10-b5ce-0f5d76b98cd2"))
    }

}
function equals(u, another) {
    if (u == undefined && another == undefined) {
        return true
    }
    if (u == undefined || another == undefined) {
        return false
    }
    return u.equals(another)
}


function NewAlterIDs(id, alterIDCount) {
    var alterIDs = []
    var prevID = id
    for (let idx = 0; idx < alterIDCount; idx++) {
        var newid = nextID(prevID)
        alterIDs[idx] = NewID(newid)
        prevID = newid
    }
    return alterIDs
}



var securityTypes = {
    'auto': consts.SECURITY_TYPE_AUTO,
    'aes-128-gcm': consts.SECURITY_TYPE_AES_128_GCM,
    'chacha20-poly1305': consts.SECURITY_TYPE_CHACHA20_POLY1305,
    'none': consts.SECURITY_TYPE_NONE,
    'zero': consts.SECURITY_TYPE_ZERO,
};


var users_data = usesave()
var users = []


function AsAccount(a) {
    var protoID = NewID(ParseString(a.id))
    if (!a.alterId)
        a.alterId = 0
    var byteCount = users_data[protoID.UUID.toString("hex")]
    var user = {
        id: protoID,
        alterIDs: NewAlterIDs(protoID.UUID, a.alterId),
        security: securityTypes[a.security],
        bytesRead: byteCount ? byteCount[0] || 0 : 0,
        bytesWrit: byteCount ? byteCount[1] || 0 : 0,
        traffic: a.traffic || 0,
        ipCount: a.ipCount || 0,
        ipCountDuration: a.ipCountDuration || 180,
        ipList: {},
    }
    users.push(user)
    return user
}


setInterval(save, 60000);
function usesave() {
    try {
        var usage = fs.readFileSync(__dirname + "/data.json");
        if (usage == "") {
            usage = {}
        }
        return usage;
    } catch (error) {
        console.log("read file error", error)
        return {}
    }
}
function save() {
    try {
        var usage = {}
        for (const i of users) {
            usage[i.id.UUID.toString("hex")] = [i.bytesRead, i.bytesWrit]
        }
        fs.writeFileSync(__dirname + "/data.json", JSON.stringify(usage));
    } catch (error) {
        console.log("write file error")
    }
}

module.exports = {
    AsAccount,
    New,
    tostring,
    NewAlterIDs
}