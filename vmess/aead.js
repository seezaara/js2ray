
const kdf = require("./kdf")
const CRC32 = require('./crypto/crc32');
const antireplay = require('./replayfilter');
const crypto = require('crypto');
const consts = require('./consts');
// ======================================== aead

function AddUser(AuthIDDecoderHolder, key, ticket) {
    AuthIDDecoderHolder.decoders[key.toString()] = {
        dec: kdf.KDF16(key, consts.KDFSaltConstAuthIDEncryptionKey),
        ticket: ticket,
    }
}

function RemoveUser(AuthIDDecoderHolder, key) {
    delete AuthIDDecoderHolder.decoders[key.toString()]
}


function Decode(aidd, data) {
    data = kdf.decrypt(data, aidd)
    return {
        t: data.readBigUInt64BE(0),
        r: data.readInt32BE(8),
        z: data.readUInt32BE(12),
        d: data
    }
}

function Match(AuthIDDecoderHolder, authID) {
    for (var v in AuthIDDecoderHolder.decoders) {
        var decode = Decode(AuthIDDecoderHolder.decoders[v].dec, authID)
        if (decode.z != CRC32(decode.d.subarray(0, 12))) {
            continue
        }
        if (decode.t < 0) {
            continue
        }

        if (Math.abs(Number(decode.t) - (Math.round(new Date() / 1000))) > 120) {
            continue
        }

        if (!antireplay.Check(AuthIDDecoderHolder.filter, authID)) {
            return false
        }

        return AuthIDDecoderHolder.decoders[v].ticket
    }
    return undefined
}

function OpenVMessAEADHeader(key, data) {
    var authid = data.subarray(0, 16)
    var payloadHeaderLengthAEADEncrypted = data.subarray(16, 18)
    var payloadHeaderLengthAEADEncryptedTag = data.subarray(18, 34)
    var nonce = data.subarray(34, 42)
    // var bytesRead = 26 // auth id not counting
    // ==================================
    var payloadHeaderLengthAEADKey = kdf.KDF16(key, consts.KDFSaltConstVMessHeaderPayloadLengthAEADKey, authid, nonce)

    var payloadHeaderLengthAEADNonce = kdf.KDF(key, consts.KDFSaltConstVMessHeaderPayloadLengthAEADIV, authid, nonce).subarray(0, 12)

    try {
        const decipher = crypto.createDecipheriv('aes-128-gcm', payloadHeaderLengthAEADKey, payloadHeaderLengthAEADNonce);
        decipher.setAuthTag(payloadHeaderLengthAEADEncryptedTag);
        decipher.setAAD(authid);
        var decryptedAEADHeaderLengthPayloadResult = Buffer.concat([decipher.update(payloadHeaderLengthAEADEncrypted), decipher.final()])
    } catch (error) {
        log(error)
        return
    }
    var length = decryptedAEADHeaderLengthPayloadResult.readUInt16BE(0) + 42



    // ============================= 
    var payloadHeaderAEADKey = kdf.KDF16(key, consts.KDFSaltConstVMessHeaderPayloadAEADKey, authid, nonce)

    var payloadHeaderAEADNonce = kdf.KDF(key, consts.KDFSaltConstVMessHeaderPayloadAEADIV, authid, nonce).subarray(0, 12)

    // 16 == AEAD Tag size  
    var payloadHeaderAEADEncrypted = data.subarray(42, length)
    var payloadHeaderAEADEncryptedTag = data.subarray(length, length + 16)
    // bytesRead += length + 16 - 42

    try {
        const decipher2 = crypto.createDecipheriv('aes-128-gcm', payloadHeaderAEADKey, payloadHeaderAEADNonce);
        decipher2.setAuthTag(payloadHeaderAEADEncryptedTag);
        decipher2.setAAD(authid);
        var decryptedAEADHeaderPayloadR = Buffer.concat([decipher2.update(payloadHeaderAEADEncrypted), decipher2.final()])
    } catch (error) {
        log(error)
        return
    }

    // return [decryptedAEADHeaderPayloadR, bytesRead]
    return decryptedAEADHeaderPayloadR
}


//cmd [124 80 97 161 224 216 179 163 214 156 7 219 35 98 9 153]
//kdf [55 0 90 119 5 224 136 11 199 243 190 121 83 230 208 193] 
// ====================================================== FUNCTIONS

module.exports = {
    AddUser,
    RemoveUser,
    Match,
    OpenVMessAEADHeader
}