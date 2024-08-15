"use strict";

const crypto = require('crypto');
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


// 2 'auto'
// 3 'aes-128-gcm'
// 4 'chacha20-poly1305'
// 5 'none'
// 6 'zero'

var securityTypes = {
    'auto': consts.SECURITY_TYPE_AUTO,
    'aes-128-gcm': consts.SECURITY_TYPE_AES_128_GCM,
    'chacha20-poly1305': consts.SECURITY_TYPE_CHACHA20_POLY1305,
    'none': consts.SECURITY_TYPE_NONE,
    'zero': consts.SECURITY_TYPE_ZERO,
};
var users = {}

function addUsers(tag, data_user) {
    if (users[tag] == undefined)
        users[tag] = {}
    for (var i in data_user) {
        parseUser(tag, data_user[i])
    }
    return users[tag];
}


function parseUser(tag, a) {
    const is_account = typeof a.id == "object" && a.alterIDs

    if (!is_account)
        var id = a.id
    else {
        if (!Buffer.isBuffer(a.id.UUID)) {
            a.id.UUID = Buffer.from(a.id.UUID)
            a.id.cmdKey = Buffer.from(a.id.cmdKey)
            if (a.alterIDs.length != 0) {
                for (const p in a.alterIDs) {
                    a.alterIDs[p].UUID = Buffer.from(a.alterIDs[p].UUID)
                    a.alterIDs[p].cmdKey = Buffer.from(a.alterIDs[p].cmdKey)
                }
            }
        }
        var id = tostring(a.id.UUID)
    }
    if (id in users[tag]) {
        var user = users[tag][id]
        user.bytesRead = a.bytesRead != undefined ? a.bytesRead : user.bytesRead
        user.bytesWrit = a.bytesWrit != undefined ? a.bytesWrit : user.bytesWrit
        user.traffic = a.traffic != undefined ? a.traffic : user.traffic
        user.ipCount = a.ipCount != undefined ? a.ipCount : user.ipCount
        user.ipCountDuration = a.ipCountDuration != undefined ? a.ipCountDuration : user.ipCountDuration
        user.email = a.email != undefined ? a.email : user.email
        user.expire = a.expire != undefined ? a.expire : user.expire
        user.deactive = a.deactive != undefined ? a.deactive : user.deactive
        user.ipList = a.ipList != undefined ? a.ipList : user.ipList
        user.ipWarning = a.ipWarning != undefined ? a.ipWarning : user.ipWarning
        user.ipBlock = a.ipBlock != undefined ? a.ipBlock : user.ipBlock
    } else {
        var user = {
            bytesRead: a.bytesRead || 0,
            bytesWrit: a.bytesWrit || 0,
            traffic: a.traffic || 0,
            ipCount: a.ipCount || 0,
            ipCountDuration: a.ipCountDuration || 600,
            email: a.email,
            expire: a.expire,
            deactive: a.deactive || 0,
            ipList: a.ipList || {},
            ipWarning: a.ipWarning || {},
            ipBlock: a.ipBlock || {},
        }
        users[tag][id] = user
    }
    if (!is_account) {
        var protoID = NewID(ParseString(id))
        if (!a.alterId)
            a.alterId = 0

        user.id = protoID
        user.alterIDs = NewAlterIDs(protoID.UUID, a.alterId)
        user.security = securityTypes[a.security || 'auto']
    } else {
        user.id = a.id
        user.alterIDs = a.alterIDs
        user.security = a.security
    }
    return user
}

function getUser(tag, id) {
    if (typeof id == "string") {
        return users[tag][id]
    } else if (tag == undefined) {
        return users;
    } else if (id == undefined) {
        return users[tag];
    }
}

function getUserByEmail(tag, email) {
    var sub_user = {}
    for (var i in users[tag]) {
        if (users[tag][i].email == email) {
            sub_user[i] = users[tag][i]
        }
    }
    return sub_user;
}

function removeUser(tag, id) {
    users[tag][id].deactive = true
    return delete users[tag][id]
}
// ================================================== stored

module.exports = {
    addUsers,
    getUser,
    getUserByEmail,
    removeUser,
    New,
    tostring,
    NewAlterIDs
}