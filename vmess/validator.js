const crypto = require("crypto"),
    long = require("./crypto/long"),
    _accont = require("./account"),
    aead = require('./aead'),
    antireplay = require('./replayfilter');


function init(users_config) {
    var users = []
    var AuthIDDecoderHolder = {
        decoders: {},
        filter: antireplay.NewReplayFilter(120)
    }

    var nowSec = unix()

    for (const data of users_config) {
        var user = _accont.AsAccount(data)
        if (data.alterId == 0) {
            aead.AddUser(AuthIDDecoderHolder, user.id.cmdKey, user)
        } else {
            users.push({
                user,
                lastSec: (nowSec - cacheDurationSec),
            })
        }
    }
    NewTimedUserValidator(AuthIDDecoderHolder, users);
}

function Close() {
    return v.task.close()
}

///====================================================


const updateInterval = 10
const cacheDurationSec = 120

var tuv;

function NewTimedUserValidator(AuthIDDecoderHolder, users) {
    tuv = {
        users: users,
        userHash: {},
        baseTime: unix() - cacheDurationSec * 2,
        aeadDecoderHolder: AuthIDDecoderHolder
    }
    tuv.task = periodic(function () {
        updateUserHash(tuv)
    }, updateInterval)
    tuv.task.start()
}

function generateNewHashes(v, nowSec, user) {
    var genEndSec = nowSec + cacheDurationSec
    function genHashForID(id) {
        var genBeginSec = user.lastSec
        // var idHash = hasher('md5', getUUIDBuffer(id))
        if (genBeginSec < nowSec - cacheDurationSec) {
            genBeginSec = nowSec - cacheDurationSec
        }
        for (var ts = genBeginSec; ts <= genEndSec; ts++) {
            var hashValue = hasher('md5', id.UUID).update(uint64ToBuffer(ts)).digest("hex");
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

function updateUserHash(v) {
    var nowSec = (unix())

    for (var user of v.users) {
        generateNewHashes(v, nowSec, user)
    }

    var expire = (unix() - cacheDurationSec)
    if (expire > v.baseTime) {
        removeExpiredHashes(v, (expire - v.baseTime))
    }
}

function GetAEAD(userHash) {
    return aead.Match(tuv.aeadDecoderHolder, userHash.subarray(0, 16))
}

function Get(authInfo) {
    if (authInfo in tuv.userHash) {
        const cacheItem = tuv.userHash[authInfo]
        return [cacheItem.user.user, uint64ToBuffer(cacheItem.timeInc + tuv.baseTime)]
    }
}


// ================================================= utils

function uint64ToBuffer(uint64, byteOrder = false /* BE */) {
    const numbers = long.fromNumber(uint64, true).toBytes(byteOrder);
    return Buffer.from(numbers);
}

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
    Close,
    GetAEAD,
    Get,
    OpenVMessAEADHeader: aead.OpenVMessAEADHeader
} 