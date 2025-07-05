"use strict";

const jsSha = require("./crypto/sha3");
const crypto = require("crypto");
const consts = require("./consts")
const event = require("./../../core/event")

function uint64ToBuffer(uint64) {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(uint64), 0);
    return buf;
}

function ntb(num, len = 2, byteOrder = 0) {
    const buf = Buffer.alloc(len);
    if (len > 0 && num >= 0 && num <= Math.pow(256, len) - 1) {
        if (byteOrder === 0) {
            buf.writeUIntBE(num, 0, len);
        } else {
            buf.writeUIntLE(num, 0, len);
        }
    }
    return buf;
}


function hash(algorithm, buffer) {
    const hs = crypto.createHash(algorithm);
    hs.update(buffer);
    return hs.digest();
}

function createChacha20Poly1305Key(key) {
    const md5Key = hash('md5', key);
    return Buffer.concat([md5Key, hash('md5', md5Key)]);
}

function shake128(buffer) {
    let buffered = Buffer.alloc(0);
    let iter = 0;
    return {
        nextBytes: function nextBytes(n) {
            const end = iter + n
            if (end > buffered.length) {
                const hash = jsSha.shake128.create(buffered.length * 8 + 512);

                hash.update(buffer);
                buffered = Buffer.from(hash.arrayBuffer());
            }

            const bytes = buffered.subarray(iter, end);
            iter = end;
            return bytes;
        }
    };
}


function fnv1a(buffer) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < buffer.length; ++i) {
        hash ^= buffer[i];
        hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    }
    const buf = Buffer.alloc(4);
    buf.writeUIntBE(hash >>> 0, 0, 4);
    return buf;
}


function encrypt(plaintext, app) {
    if (app._dataEncIV) {
        const security = app._security;
        let tag = null;
        const nonce = Buffer.concat([ntb(app._cipherNonce), app._dataEncIV.subarray(2, 12)]);
        let ciphertext = null;
        if (security === consts.SECURITY_TYPE_AES_128_GCM) {
            const cipher = crypto.createCipheriv('aes-128-gcm', app._dataEncKey, nonce);
            ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
            tag = cipher.getAuthTag();
            app._cipherNonce += 1;
            if (app._cipherNonce > 65535)
                app._cipherNonce = 0
        }
        else if (security === consts.SECURITY_TYPE_CHACHA20_POLY1305) {
            const cipher = crypto.createCipheriv('chacha20-poly1305', app._dataEncKeyForChaCha20, nonce, {
                authTagLength: 16
            })
            ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
            tag = cipher.getAuthTag();
            app._cipherNonce += 1;
            if (app._cipherNonce > 65535)
                app._cipherNonce = 0
        }
        return Buffer.concat([ciphertext, tag]);
    }
    return Buffer.alloc(0)
}
function decrypt(ciphertext, app) {
    if (app._dataDecIV) {
        const tag = ciphertext.subarray(-16);
        ciphertext = ciphertext.subarray(0, -16)
        const security = app._security;
        const nonce = Buffer.concat([ntb(app._decipherNonce), app._dataDecIV.subarray(2, 12)]);
        if (security === consts.SECURITY_TYPE_AES_128_GCM) {
            try {
                const decipher = crypto.createDecipheriv('aes-128-gcm', app._dataDecKey, nonce);
                decipher.setAuthTag(tag);
                const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
                app._decipherNonce += 1;
                if (app._decipherNonce > 65535)
                    app._decipherNonce = 0
                return plaintext;
            } catch (err) {
                return null;
            }
        }
        else if (security === consts.SECURITY_TYPE_CHACHA20_POLY1305) {
            try {
                const decipher = crypto.createDecipheriv('chacha20-poly1305', app._dataDecKeyForChaCha20, nonce, {
                    authTagLength: 16
                });
                decipher.setAuthTag(tag)
                const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
                app._decipherNonce += 1;
                if (app._decipherNonce > 65535)
                    app._decipherNonce = 0
                return plaintext;
            } catch (err) {
                return null;
            }
        }
    }
}

function getChunks(buffer, maxSize) {
    const totalLen = buffer.length;
    const bufs = [];
    let ptr = 0;
    while (ptr < totalLen - 1) {
        bufs.push(buffer.subarray(ptr, ptr + maxSize));
        ptr += maxSize;
    }
    if (ptr < totalLen) {
        bufs.push(buffer.subarray(ptr));
    }
    return bufs;
}

// ================================================= utils
function trafficlimit(user) {
    if (user.bytesRead + user.bytesWrit >= user.traffic) {
        if (!user.maxtraffic) {
            event.emit("traffic", user.id.UUID)
            user.maxtraffic = true
        }
        return true;
    }
}

function iplimit(ip, user) {
    var now = Math.round(new Date() / 1000)
    if (user.ipCount && !(ip in user.ipList)) {
        if (Object.keys(user.ipList).length >= user.ipCount) {
            // ============ if before 10 min
            if (user.ipBlock[ip] && user.ipBlock[ip] + user.ipCountDuration > now) {
                // ======================================= soft allow for 1 or 2 ip
                if (ip in user.ipWarning) {
                    if (user.ipWarning[ip] + user.ipCountDuration / 20 < now) {
                        delete user.ipBlock[ip]
                        user.maxip = false
                        return false
                    }
                } else if (Object.keys(user.ipWarning).length < Math.max(1, Math.round(user.ipCount / 2.1))) {
                    user.ipWarning[ip] = now
                }
                if (!user.maxip) {
                    event.emit("ip", user.id.UUID)
                    user.maxip = true
                }
                return true
                // ===================================================
            } else {
                delete user.ipBlock[ip]
            }
            //================================================ clear ips
            for (const i in user.ipList) {
                if (user.ipList[i] + user.ipCountDuration < now) {
                    delete user.ipList[i]
                }
            }
            for (const i in user.ipWarning) {
                if (user.ipWarning[i] + user.ipCountDuration < now) {
                    delete user.ipWarning[i]
                }
            }
            //===================================================
            const keys = Object.keys(user.ipList)
            if (keys.length >= user.ipCount) {
                var wip = keys.reduce((key, v) => user.ipList[v] < user.ipList[key] ? v : key);
                user.ipBlock[wip] = user.ipList[wip]
                delete user.ipList[wip];
            }
            for (const i in user.ipBlock) {
                if (user.ipBlock[i] + user.ipCountDuration < now) {
                    delete user.ipBlock[i]
                }
            }
        }
    }
    user.ipList[ip] = now
    if (user.maxip)
        user.maxip = false
    return false
}



module.exports = {
    ntb,
    hash,
    createChacha20Poly1305Key,
    shake128,
    uint64ToBuffer,
    fnv1a,
    encrypt,
    decrypt,
    getChunks,
    trafficlimit,
    update_ip: iplimit,
    iplimit
}


