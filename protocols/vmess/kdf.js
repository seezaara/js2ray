"use strict";
const { hmac } = require('./crypto/hmac/hmac.js')
const { sha256 } = require('./crypto/hmac/sha256.js')
const consts = require("./consts")
const crypto = require('crypto');

function KDF(key, ...paths) {
    var hmacCreator = { value: consts.KDFSaltConstVMessAEADKDF }
    for (const v of paths) {
        hmacCreator = { value: Buffer.from(v), parent: hmacCreator }
    }

    var hmacf = Create(hmacCreator)
    return Buffer.from(hmacf.update(key).digest("binary"))
}

function Create(h) {
    if (h.parent == undefined) {
        return hmac.create(sha256, h.value)
    }
    return hmac.create(wrapConstructor(Create, h.parent), h.value)
}

function wrapConstructor(hashConstructor, ctx) {
    const hashC = (message) => hashConstructor(ctx).update(toBytes(message)).digest();
    const tmp = hashConstructor(ctx);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashConstructor(ctx);
    return hashC;
}

function KDF16(key, ...path) {
    return KDF(key, ...path).subarray(0, 16)
}

function encrypt(textEncrypted, secretKeyInput) {
    switch (secretKeyInput.length) {
        case 16:
            var algo = 'aes-128-ecb';
            break;
        case 24:
            var algo = 'aes-192-ecb'
            break;
        case 32:
            var algo = 'aes-256-ecb'
            break;
        default:
            throw Error(`invaled key length`);
    }
    return crypto.createCipheriv(algo, secretKeyInput, '').update(textEncrypted)
}

function decrypt(textEncrypted, secretKeyInput) {
    switch (secretKeyInput.length) {
        case 16:
            var algo = 'aes-128-ecb';
            break;
        case 24:
            var algo = 'aes-192-ecb'
            break;
        case 32:
            var algo = 'aes-256-ecb'
            break;
        default:
            throw Error(`invaled key length`);
    }
    // return crypto.createDecipheriv(algo, secretKeyInput, '').update(textEncrypted)
    return crypto.createDecipheriv(algo, secretKeyInput, '').update(Buffer.concat([textEncrypted, Buffer.alloc(1)]))
}
module.exports = {
    decrypt,
    encrypt,
    KDF,
    KDF16
}