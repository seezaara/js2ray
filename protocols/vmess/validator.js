"use strict";
const crypto = require("crypto"),
    common = require("./common"),
    account = require("./account"),
    store = require("./store"),
    aead = require('./aead'),
    antireplay = require('./replayfilter');
store.getUser = account.getUser

const tuvs = {}

function init(bound) {
    if (bound.tag == undefined)
        bound.tag = (Math.random() + 1).toString(36).substring(3)
    const tuv = {
        users: [],
        userHash: {},
        baseTime: unix() - cacheDurationSec * 2,
        aeadDecoderHolder: {
            decoders: {},
            filter: antireplay.NewReplayFilter(120)
        },
    }
    tuv.task = periodic(updateUserHash.bind(tuv), updateInterval)
    tuvs[bound.tag] = tuv
    if (bound.users && bound.users.length != 0) {
        addUsers(bound.tag, bound.users)
    } else {
        addUsers(bound.tag, store.get(bound.tag))
    }
    return {
        get: getRandomUser.bind(tuv),
        check: checkUser.bind(tuv),
    }
}
///====================================================


function addUsers(tag, users) {
    const tuv = tuvs[tag]
    const user_account = account.addUsers(tag, users)
    activeUsers(tuv, user_account)
    store.save()
    checkUserHash(tuv)
}

function activeUsers(tuv, users) {
    if (!users)
        return
    for (const user of Object.values(users)) {
        if (user.alterIDs.length == 0) {
            aead.AddUser(tuv.aeadDecoderHolder, user.id.cmdKey, user)
        } else {
            tuv.users.push({
                user,
                lastSec: (unix() - cacheDurationSec),
            })
        }
    }
}

function removeUsers(tag, ids) {
    const tuv = tuvs[tag]
    for (const id of ids) {
        const user = account.getUser(tag, id)
        if (user) {
            account.removeUser(tag, id)
            if (user.alterIDs.length == 0)
                aead.RemoveUser(tuv.aeadDecoderHolder, user.id.cmdKey)
            else {
                for (key in v.userHash) {
                    if (v.userHash[key].user.user.id.UUID == id) {
                        delete v.userHash[key]
                    }
                }
            }
            checkUserHash(tuv)
            store.save() 
        }
    }
    return true;
}

function checkUserHash(tuv) {
    if (tuv.users.length != 0) {
        tuv.task.start()
    } else {
        tuv.userHash = {}
        tuv.task.close()
    }
}

function getRandomUser() {
    const keys = Object.keys(this.aeadDecoderHolder.decoders)
    if (keys.length != 0) {
        const key = keys[Math.floor(Math.random() * keys.length)]
        const cacheItem = this.aeadDecoderHolder.decoders[key]
        return [true, cacheItem.ticket]
        // return [true, cacheItem.ticket, Buffer.from(key, "hex")]
    } else {
        const keys = Object.keys(this.userHash)
        const key = keys[Math.floor(Math.random() * keys.length)]
        const cacheItem = this.userHash[key]
        return [false, cacheItem.user.user, Buffer.from(key, "hex"), common.uint64ToBuffer(cacheItem.timeInc + this.baseTime)]
    }
}

function checkUser(authInfo, isaead) {
    if (isaead)
        return aead.Match(this.aeadDecoderHolder, authInfo)
    else if (authInfo in this.userHash) {
        const cacheItem = this.userHash[authInfo]
        return [cacheItem.user.user, common.uint64ToBuffer(cacheItem.timeInc + this.baseTime)]
    }
}

const updateInterval = 10
const cacheDurationSec = 120


function generateNewHashes(v, nowSec, user) {
    var genEndSec = nowSec + cacheDurationSec
    function genHashForID(id) {
        var genBeginSec = user.lastSec
        // var idHash = hasher('md5', getUUIDBuffer(id))
        if (genBeginSec < nowSec - cacheDurationSec) {
            genBeginSec = nowSec - cacheDurationSec
        }
        for (var ts = genBeginSec; ts <= genEndSec; ts++) {
            var hashValue = hasher('md5', id.UUID).update(common.uint64ToBuffer(ts)).digest("hex");
            v.userHash[hashValue] = {
                user: user,
                timeInc: ts - v.baseTime,
            }
        }
    }
    genHashForID(user.user.id)
    for (id of user.user.alterIDs) {
        genHashForID(id)
    }
    user.lastSec = genEndSec
}

function removeExpiredHashes(v, expire) {
    for (key in v.userHash) {
        if (v.userHash[key].timeInc < expire) {
            delete v.userHash[key]
        }
    }
}

function updateUserHash() {
    var nowSec = (unix())

    for (var user of this.users) {
        generateNewHashes(this, nowSec, user)
    }

    var expire = (unix() - cacheDurationSec)
    if (expire > this.baseTime) {
        removeExpiredHashes(this, (expire - this.baseTime))
    }
}



// ================================================= utils


function hasher(alg, key) {
    return crypto.createHmac(alg, key);
}


function unix() {
    return Math.round(new Date() / 1000)
}

function periodic(cal, timer) {
    var inter = undefined;
    return {
        start: function () {
            this.close()
            inter = setInterval(cal, timer * 1000)
            cal()
        },
        close: function () {
            if (inter)
                clearInterval(inter)
        }
    }
}


module.exports = {
    init,
    addUsers,
    removeUsers,
    getUser: account.getUser,
    getUserByEmail: account.getUserByEmail,
    OpenVMessAEADHeader: aead.OpenVMessAEADHeader,
    SealVMessAEADHeader: aead.SealVMessAEADHeader
} 