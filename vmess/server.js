
const tunnel = require("./tunnel")
const validator = require("./validator")
const AdvancedBuffer = require("./advanced-buffer")
const jsSha = require("./crypto/sha3");
const kdf = require("./kdf")
const event = require("./event")
const consts = require("./consts")
const crypto = require("crypto")

const ATYP_V4 = 0x01;
const ATYP_DOMAIN = 0x02;
const ATYP_V6 = 0x03;
function DecodeRequestHeader(buffer) {
    var app = this.app
    if (!app._isHeaderRecv) {
        if (app._isConnecting) {
            app._staging = Buffer.concat([app._staging, buffer]);
            return;
        }

        if (buffer.length < 16) {
            return log(`fail to parse request header: ${buffer.toString("hex")}`);
        }

        const reqCommand = Buffer.from(buffer.subarray(16));
        var aeadUser = validator.GetAEAD(buffer)
        if (aeadUser == undefined) {
            var dataoffset = 16
            const user = validator.Get(buffer.subarray(0, 16).toString("hex"));
            if (user == undefined)
                return log(`cannot find ${buffer.subarray(0, 16).toString("hex")} in cache, maybe a wrong auth info`)
            var ts = user[1]
            aeadUser = user[0]
            var iv = hash('md5', Buffer.concat([ts, ts, ts, ts]))
            var decipher = crypto.createDecipheriv('aes-128-cfb', aeadUser.id.cmdKey, iv);
            decipher.subarray = function (a, b) {
                return this.update(reqCommand.subarray(a, b))
            }
            app.user = aeadUser
            app._isAEADRequest = false
        } else if (typeof aeadUser == "object") {
            var decipher = validator.OpenVMessAEADHeader(aeadUser.id.cmdKey, buffer)
            // 16 + 12 + 12 + 18
            var dataoffset = 58
            if (decipher == undefined) {
                return log("AEAD read failed")
            }
            app.user = aeadUser
            app._isAEADRequest = true
        } else {
            return log(`invalid user`);
        }
        if (aeadUser.ipCount != 0 && iplimit(app, aeadUser))
            return log(`maximum ip used by user ${aeadUser.id.UUID.toString("hex")}`)

        if (aeadUser.traffic != 0 && trafficlimit(aeadUser)) {
            return log(`maximum traffic ${aeadUser.traffic / 1024 / 1024}MB (bytesRead:${aeadUser.bytesRead},bytesWrit:${aeadUser.bytesWrit}) used by user ${aeadUser.id.UUID.toString("hex")}`)
        }

        if (reqCommand.length < 41) {
            return log(`request command is too short: ${reqCommand.length}bytes, command=${reqCommand.toString('hex')}`);
        }

        const reqHeader = decipher.subarray(0, 41);
        const ver = reqHeader[0];

        if (ver !== 0x01) {
            return log(`invalid version number: ${ver}`);
        }

        app._dataDecIV = reqHeader.subarray(1, 17);
        app._dataDecKey = reqHeader.subarray(17, 33);
        if (app._isAEADRequest) {
            app._dataEncIV = hash('sha256', app._dataDecIV).subarray(0, 16);
            app._dataEncKey = hash('sha256', app._dataDecKey).subarray(0, 16);
        } else {
            app._dataEncIV = hash('md5', app._dataDecIV);
            app._dataEncKey = hash('md5', app._dataDecKey);

        }
        app._dataDecKeyForChaCha20 = createChacha20Poly1305Key(app._dataDecKey);
        app._dataEncKeyForChaCha20 = createChacha20Poly1305Key(app._dataEncKey);
        app._chunkLenDecMaskGenerator = shake128(app._dataDecIV);
        app._chunkLenEncMaskGenerator = shake128(app._dataEncIV);
        app._responseHeader = reqHeader[33];
        app._opt = reqHeader[34];
        const paddingLen = reqHeader[35] >> 4;

        // 2 'auto'
        // 3 'aes-128-gcm'
        // 4 'chacha20-poly1305'
        // 5 'none'
        // 6 'zero'
        const securityType = reqHeader[35] & 0x0F;
        if (!(aeadUser.security == 2 || aeadUser.security == undefined || securityType == 2) && securityType != aeadUser.security) {
            return log(`invalid securety type`);
        }
        //===========
        const cmd = reqHeader[37];
        if (![0x01, 0x02].includes(cmd)) {
            return log(`unsupported cmd: ${cmd}`);
        }
        const port = reqHeader.readUInt16BE(38);
        const addrType = reqHeader[40];
        let addr = null;
        let offset = 40;
        if (addrType === ATYP_V4) {
            if (reqCommand.length < 45) {
                return log(`request command is too short ${reqCommand.length}bytes to get ipv4, command=${reqCommand.toString('hex')}`);
            }

            addr = decipher.subarray(41, 45);
            offset += 4;
        } else if (addrType === ATYP_V6) {
            if (reqCommand.length < 57) {
                return log(`request command is too short: ${reqCommand.length}bytes to get ipv6, command=${reqCommand.toString('hex')}`);
            }

            addr = decipher.subarray(41, 57);
            offset += 16;
        } else if (addrType === ATYP_DOMAIN) {
            if (reqCommand.length < 42) {
                return log(`request command is too short: ${reqCommand.length}bytes to get host name, command=${reqCommand.toString('hex')}`);
            }

            const addrLen = decipher.subarray(41, 42)[0];

            if (reqCommand.length < 42 + addrLen) {
                return log(`request command is too short: ${reqCommand.length}bytes, command=${reqCommand.toString('hex')}`);
            }

            addr = decipher.subarray(42, 42 + addrLen);
            offset += 1 + addrLen;
        } else {
            return log(`unknown address type: ${addrType}, command=${reqHeader.toString('hex')}`);
        }

        if (reqCommand.length < offset + paddingLen + 4) {
            return log(`request command is too short: ${reqCommand.length}bytes to get padding and f, command=${reqCommand.toString('hex')}`);
        }

        const padding = decipher.subarray(offset, offset + paddingLen);
        offset += paddingLen;
        const f = decipher.subarray(offset, offset + 4);

        const plainReqHeader = Buffer.from([...reqHeader.subarray(0, 41), ...(addrType === ATYP_DOMAIN ? [addr.length] : []), ...addr, ...padding]);

        if (fnv1a(plainReqHeader).equals(f)) {
            return log('fail to verify request command');
        }
        const data = buffer.subarray(dataoffset + plainReqHeader.length + 4);
        app._security = securityType;
        app._isConnecting = true;

        tunnel.connect(addrType === ATYP_DOMAIN ? addr.toString() : iptoString(addr), port, cmd, function () {
            app.outbound = this.outbound
            app._adBuf.put(Buffer.concat([data, app._staging]), app);
            app._isHeaderRecv = true;
            app._isConnecting = false;
            app._staging = null;
        }, EncodeResponseBody.bind(this));
    } else {
        if (app.user.traffic != 0 && trafficlimit(app.user))
            return log(`maximum traffic ${app.user.traffic / 1024 / 1024}MB (bytesRead:${app.user.bytesRead},bytesWrit:${app.user.bytesWrit}) used by user ${app.user.id.UUID.toString("hex")}`);
        app._adBuf.put(buffer, app);
    }
}

function DecodeRequestBody(chunk, app) {
    if ([consts.SECURITY_TYPE_AES_128_GCM, consts.SECURITY_TYPE_CHACHA20_POLY1305].includes(this._security)) {
        const tag = chunk.slice(-16);
        const data = decrypt.call(app, chunk.slice(2, -16), tag);
        if (data === null) {
            return log(`fail to verify data chunk, `, chunk + "");
        }
        app.user.bytesWrit += data.length
        return app.outbound(data);
    }
    app.user.bytesWrit += chunk.length - 2
    return app.outbound(chunk.slice(2));
}

function EncodeResponseHeader(app) {
    var outBuffer = Buffer.from([app._responseHeader, 0x00, 0x00, 0x00])
    if (!app._isAEADRequest) {
        var encryptionWriter = crypto.createCipheriv('aes-128-cfb', app._dataEncKey, app._dataEncIV);
        return encryptionWriter.update(outBuffer);
    } else {
        const aeadResponseHeaderLengthEncryptionKey = kdf.KDF16(app._dataEncKey, consts.KDFSaltConstAEADRespHeaderLenKey)
        const aeadResponseHeaderLengthEncryptionIV = kdf.KDF(app._dataEncIV, consts.KDFSaltConstAEADRespHeaderLenIV).subarray(0, 12)
        const aeadResponseHeaderLengthEncryptionBuffer = Buffer.allocUnsafe(2);
        aeadResponseHeaderLengthEncryptionBuffer.writeUInt16BE(outBuffer.length)

        const cipher = crypto.createCipheriv('aes-128-gcm', aeadResponseHeaderLengthEncryptionKey, aeadResponseHeaderLengthEncryptionIV);
        var AEADEncryptedLength = Buffer.concat([cipher.update(aeadResponseHeaderLengthEncryptionBuffer), cipher.final(), cipher.getAuthTag()])



        const aeadResponseHeaderPayloadEncryptionKey = kdf.KDF16(app._dataEncKey, consts.KDFSaltConstAEADRespHeaderPayloadKey)
        const aeadResponseHeaderPayloadEncryptionIV = kdf.KDF(app._dataEncIV, consts.KDFSaltConstAEADRespHeaderPayloadIV).subarray(0, 12)


        const cipher2 = crypto.createCipheriv('aes-128-gcm', aeadResponseHeaderPayloadEncryptionKey, aeadResponseHeaderPayloadEncryptionIV);

        var aeadEncryptedHeaderPayload = Buffer.concat([cipher2.update(outBuffer), cipher2.final(), cipher2.getAuthTag()])
        return Buffer.concat([AEADEncryptedLength, aeadEncryptedHeaderPayload])
    }
}
function EncodeResponseBody(buffer) {
    const app = this.app
    app.user.bytesRead += buffer.length
    if (!app._isHeaderSent) {
        app._isHeaderSent = true;
        this.write(EncodeResponseHeader(app))
        const chunks = getChunks(buffer, 0x3fff).map(resolveChunk.bind(app));
        for (const iterator of chunks) {
            this.write(iterator)
        }
    } else {
        const chunks = getChunks(buffer, 0x3fff).map(resolveChunk.bind(app));
        for (const iterator of chunks) {
            this.write(iterator)
        }
    }
}

function connect(socket, ip) {
    socket.app = {}
    socket.app.ip = ip
    socket.app._staging = Buffer.alloc(0)
    socket.app._opt = 0x05
    socket.app._isConnecting = false;
    socket.app._isHeaderSent = false;
    socket.app._isHeaderRecv = false;

    socket.app._adBuf = new AdvancedBuffer({ getPacketLength: onReceivingLength.bind(socket.app) });
    socket.app._adBuf.on('data', DecodeRequestBody.bind(socket.app));
}


function close() {
    this.app._adBuf.clear();
    this.app._adBuf = null;
    this.app._host = null;
    this.app._port = null;
    this.app._staging = null;
    this.app._dataEncKey = null;
    this.app._dataEncKeyForChaCha20 = null;
    this.app._dataEncIV = null;
    this.app._dataDecKey = null;
    this.app._dataDecKeyForChaCha20 = null;
    this.app._dataDecIV = null;
    this.app._chunkLenEncMaskGenerator = null;
    this.app._chunkLenDecMaskGenerator = null;
}


// =================================================  sender 
function resolveChunk(chunk) {
    let _chunk = chunk;
    if ([consts.SECURITY_TYPE_AES_128_GCM, consts.SECURITY_TYPE_CHACHA20_POLY1305].includes(this._security)) {  
        _chunk = Buffer.concat(this.encrypt(_chunk));
    }
    let _len = _chunk.length;
    if (this._opt === 0x05) {
        const mask = this._chunkLenEncMaskGenerator.nextBytes(2).readUInt16BE(0);
        _len = mask ^ _len;
    }
    return Buffer.concat([ntb(_len), _chunk]);
}
function getChunks(buffer, maxSize) {
    const totalLen = buffer.length;
    const bufs = [];
    let ptr = 0;
    while (ptr < totalLen - 1) {
        bufs.push(buffer.slice(ptr, ptr + maxSize));
        ptr += maxSize;
    }
    if (ptr < totalLen) {
        bufs.push(buffer.slice(ptr));
    }
    return bufs;
}

// ================================================= utils
function trafficlimit(user) {
    if (user.bytesRead + user.bytesWrit > user.traffic) {
        if (!user.maxtraffic) {
            event.emit("traffic", user.id.UUID)
            user.maxtraffic = true
        }
        return true;
    }
}
function iplimit(app, user) {
    var now = Math.round(new Date() / 1000)
    if (!(app.ip in user.ipList)) {
        if (Object.keys(user.ipList).length >= user.ipCount) {
            for (const i in user.ipList) {
                if (user.ipList[i] + user.ipCountDuration < now) {
                    delete user.ipList[i]
                }
            }
            if (Object.keys(user.ipList).length >= user.ipCount) {
                if (!user.maxip) {
                    event.emit("ip", user.id.UUID)
                    user.maxip = true
                }
                return true;
            }
        }
        if (user.maxip)
            user.maxip = false
    }
    user.ipList[app.ip] = now
}

function iptoString(buff, offset, length) {
    offset = ~~offset;
    length = length || (buff.length - offset);

    var result = [];
    var i;
    if (length === 4) {
        // IPv4
        for (i = 0; i < length; i++) {
            result.push(buff[offset + i]);
        }
        result = result.join('.');
    } else if (length === 16) {
        // IPv6
        for (i = 0; i < length; i += 2) {
            result.push(buff.readUInt16BE(offset + i).toString(16));
        }
        result = result.join(':');
        result = result.replace(/(^|:)0(:0)*:0(:|$)/, '$1::$3');
        result = result.replace(/:{3,4}/, '::');
    }

    return result;
};

function encrypt(plaintext) {
    const security = this._security;
    const nonce = Buffer.concat([ntb(this._cipherNonce), this._dataEncIV.slice(2, 12)]);
    let ciphertext = null;
    let tag = null;
    if (security === consts.SECURITY_TYPE_AES_128_GCM) {
        const cipher = crypto.createCipheriv('aes-128-gcm', this._dataEncKey, nonce);
        ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        tag = cipher.getAuthTag();
    }
    else if (security === consts.SECURITY_TYPE_CHACHA20_POLY1305) {
        const noop = Buffer.alloc(0);
        // eslint-disable-next-line
        const result = libsodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            plaintext, noop, noop, nonce, this._dataEncKeyForChaCha20,
        );
        ciphertext = Buffer.from(result.ciphertext);
        tag = Buffer.from(result.mac);
    }
    this._cipherNonce += 1;
    return [ciphertext, tag];
}

function decrypt(ciphertext, tag) {
    const security = this._security;
    const nonce = Buffer.concat([ntb(this._decipherNonce), this._dataDecIV.slice(2, 12)]);
    if (security === consts.SECURITY_TYPE_AES_128_GCM) {
        const decipher = crypto.createDecipheriv('aes-128-gcm', this._dataDecKey, nonce);
        decipher.setAuthTag(tag);
        try {
            const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            this._decipherNonce += 1;
            return plaintext;
        } catch (err) {
            return null;
        }
    }
    else if (security === consts.SECURITY_TYPE_CHACHA20_POLY1305) {
        const noop = Buffer.alloc(0);
        try {
            // eslint-disable-next-line
            const plaintext = libsodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(
                noop, ciphertext, tag, noop, nonce, this._dataDecKeyForChaCha20,
            );
            this._decipherNonce += 1;
            return Buffer.from(plaintext);
        } catch (err) {
            return null;
        }
    }
}

function onReceivingLength(buffer) {
    if (buffer.length < 2) {
        return;
    }
    let len = buffer.readUInt16BE(0);
    if (this._opt === 0x05) {
        const mask = this._chunkLenDecMaskGenerator.nextBytes(2).readUInt16BE(0);
        len = mask ^ len;
    }
    return 2 + len;
}


function ntb(num, len = 2, byteOrder = 0) {
    if (len < 1) {
        throw Error('len must be greater than 0');
    }
    const buf = Buffer.alloc(len);
    if (byteOrder === 0) {
        buf.writeUIntBE(num, 0, len);
    } else {
        buf.writeUIntLE(num, 0, len);
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
    let buffered = [];
    let iter = 0;
    return {
        nextBytes: function nextBytes(n) {
            if (iter + n > buffered.length) {
                const hash = jsSha.shake128.create(buffered.length * 8 + 512);

                hash.update(buffer);
                buffered = Buffer.from(hash.arrayBuffer());
            }

            const bytes = buffered.subarray(iter, iter + n);
            iter += n;
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


module.exports = {
    message: DecodeRequestHeader, 
    connect,
    close
}