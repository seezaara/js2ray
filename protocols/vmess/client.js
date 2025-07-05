"use strict";


const common = require("./common") 
const utils = require('../../core/utils');
const validator = require("./validator")
const consts = require("./consts")
const AdvancedBuffer = require("./advanced-buffer")
const kdf = require("./kdf")
const net = require("net")
const crypto = require("crypto");

const ATYP_V4 = 0x01;
const ATYP_DOMAIN = 0x02;
const ATYP_V6 = 0x03;

function init(data, remoteNetwork) {
    var randomuser = validator.init(data).get
    return function (address, port, cmd, localConnect, localMessage, localClose) {

        // ========================================== pipe
        const pipeSocket = localMessage
        if (typeof pipeSocket == "object") {
            localMessage = pipeSocket.write.bind(pipeSocket)
            localClose = pipeSocket.destroy.bind(pipeSocket)
        }
        // ==========================================
        const app = {}
        app.localMessage = localMessage
        app.user = {}
        app._cmd = cmd;
        app._port = common.ntb(port);
        const type = getAddrType(address);
        app._atyp = type;
        app._host = (type === ATYP_DOMAIN) ? Buffer.from(address) : utils.iptoBuffer(address);


        app._staging = Buffer.alloc(0)
        // app._option = 0x05
        app._cipherNonce = 0;
        app._decipherNonce = 0;

        app._adBuf = new AdvancedBuffer({ getPacketLength: onReceivingLength });
        app._adBuf.on('data', DecodeResponseBody);

        const network = data.networks.length == 1 ? data.networks[0] : Ddata.networks[Math.floor(Math.random() * data.networks.length)]

        var socket = remoteNetwork(
            network.address,
            network.port,
            1,
            localConnect,
            DecodeResponseHeader.bind(app),
            localClose,
        )
        socket.app = app
        socket.app.close = socket.close

        const out = {
            message: EncodeRequestBody.bind(socket, randomuser),
            close: function () {
                onclose(socket.app)
                delete socket.app
            }
        }
        // ========================================== pipe
        if (typeof pipeSocket == "object") {
            pipeSocket.on("error", out.close)
            pipeSocket.on("close", out.close)
            pipeSocket.on("data", out.message)
        }
        // ==========================================
        return out
    }
}

function onerror(app, error, ind) {
    log(error, ind)
    onclose(app);
}

function onclose(app) {
    if (!app)
        return
    app._isConnecting = false;
    app._isHeaderSent = false;
    app._isHeaderRecv = false;
    if (app._adBuf)
        app._adBuf.clear();
    app._adBuf = null;
    app._host = null;
    app._port = null;
    app._staging = null;
    app._dataEncKey = null;
    app._dataEncKeyForChaCha20 = null;
    app._dataEncIV = null;
    app._dataDecKey = null;
    app._dataDecKeyForChaCha20 = null;
    app._dataDecIV = null;
    app._chunkLenEncMaskGenerator = null;
    app._chunkLenDecMaskGenerator = null;
    app.close()

}


function EncodeRequestBody(randomuser, buffer) {
    const app = this.app
    if (app) {
        if (!app._isHeaderSent) {
            app._isHeaderSent = true;
            const header = EncodeRequestHeader(app, randomuser)
            if (header) {
                if (app.user.deactive)
                    return
                app.user.bytesRead += buffer.length
                const chunks = common.getChunks(buffer, 0x3fff).map(resolveChunk.bind(app));
                this.message(Buffer.concat([header, ...chunks]))
            }
        } else {
            if (app.user.deactive)
                return
            if (app.user.traffic != 0 && common.trafficlimit(app.user))
                return onerror(app, `maximum traffic ${app.user.traffic / 1024 / 1024}MB (bytesRead:${app.user.bytesRead},bytesWrit:${app.user.bytesWrit}) used by user ${app.user.id.UUID.toString("hex")}`, 1);
            app.user.bytesRead += buffer.length
            const chunks = common.getChunks(buffer, 0x3fff).map(resolveChunk.bind(app));
            this.message(Buffer.concat(chunks))
        }
    }
}

function EncodeRequestHeader(app, randomuser) {
    if (!app._host)
        return
    const rands = crypto.randomBytes(33);
    const [isAEAD, random_user, authInfo, ts] = randomuser();
    app._isAEADRequest = isAEAD
    app.user = random_user

    if (random_user.traffic != 0 && common.trafficlimit(random_user)) {
        return onerror(app, `maximum traffic ${random_user.traffic / 1024 / 1024}MB (bytesRead:${random_user.bytesRead},bytesWrit:${random_user.bytesWrit}) used by user ${random_user.id.UUID.toString("hex")}`, 1)
    }
    // IV and Key for data chunks encryption/decryption
    app._dataEncIV = rands.subarray(0, 16);
    app._dataEncKey = rands.subarray(16, 32);

    if (isAEAD) {
        app._dataDecIV = common.hash('sha256', app._dataEncIV).subarray(0, 16);
        app._dataDecKey = common.hash('sha256', app._dataEncKey).subarray(0, 16);
        app.lengthEnKey = kdf.KDF16(app._dataDecKey, consts.KDFSaltConstAEADRespHeaderLenKey)
        app.lengthEnIV = kdf.KDF(app._dataDecIV, consts.KDFSaltConstAEADRespHeaderLenIV).subarray(0, 12)
        app.payloadEnKey = kdf.KDF16(app._dataDecKey, consts.KDFSaltConstAEADRespHeaderPayloadKey)
        app.payloadEnIV = kdf.KDF(app._dataDecIV, consts.KDFSaltConstAEADRespHeaderPayloadIV).subarray(0, 12)
    } else {
        app._dataDecIV = common.hash('md5', app._dataEncIV);
        app._dataDecKey = common.hash('md5', app._dataEncKey);
    }

    app._chunkLenEncMaskGenerator = common.shake128(app._dataEncIV);
    app._chunkLenDecMaskGenerator = common.shake128(app._dataDecIV);

    app._v = rands[32];

    const paddingLen = getRandomInt(0, 15);
    const padding = crypto.randomBytes(paddingLen);

    if (app.user.security == consts.SECURITY_TYPE_AUTO) {
        app._security = consts.SECURITY_TYPE_CHACHA20_POLY1305
        app._option = 0x0D;
    } else if (app.user.security == consts.SECURITY_TYPE_ZERO) {
        app._security = consts.SECURITY_TYPE_NONE
        app._option = 0x00;
    } else {
        app._security = app.user.security || 2
        app._option = 0x05;
    }
    if (app._security == consts.SECURITY_TYPE_CHACHA20_POLY1305) {
        app._dataEncKeyForChaCha20 = common.createChacha20Poly1305Key(app._dataEncKey);
        app._dataDecKeyForChaCha20 = common.createChacha20Poly1305Key(app._dataDecKey);
    }
    if (app._host.length > 255) {
        return onerror(app, `domain name is too long`, 1)
    }
    // create encrypted command
    let command = Buffer.from([
        0x01, // Ver
        ...app._dataEncIV, ...app._dataEncKey, app._v, app._option,
        paddingLen << 4 | app._security,
        0x00, // RSV
        app._cmd, // Cmd
        ...app._port,
        app._atyp,
        ...Buffer.concat([
            (app._atyp === ATYP_DOMAIN) ? common.ntb(app._host.length, 1) : Buffer.alloc(0),
            app._host,
        ]),
        ...padding,
    ]);
    command = Buffer.concat([command, common.fnv1a(command)]);



    if (isAEAD == false) {
        const cipher = crypto.createCipheriv(
            'aes-128-cfb',
            random_user.id.cmdKey,
            common.hash('md5', Buffer.concat([ts, ts, ts, ts])),
        );
        command = cipher.update(command);
        return Buffer.concat([authInfo, command]);
    } else if (typeof random_user == "object") {
        const aeadHeader = validator.SealVMessAEADHeader(random_user.id.cmdKey, command)
        if (aeadHeader == undefined) {
            return onerror(app, `AEAD read failed`, 1)
        }
        return aeadHeader;
    } else {
        return onerror(app, `invalid user`, 1);
    }
}


function DecodeResponseHeader(buffer) {
    const app = this
    if (!app._isHeaderRecv) {
        if (app._dataDecKey == null)
            return
        try {
            if (!app._isAEADRequest) {
                const decipher = crypto.createDecipheriv('aes-128-cfb', app._dataDecKey, app._dataDecIV);
                var header = decipher.update(buffer.subarray(0, 4));
                if (app._v !== header[0]) {
                    return onerror(app, `server response v doesn't match, expect ${app._v} but got ${header[0]}`, 1);
                }
                app._isHeaderRecv = true;
                if (!app._adBuf)
                    return onerror(app, 'fail to read _adBuf', 1);
                return app._adBuf.put(buffer.subarray(4 + header[3]), app);
            } else {

                const decipher = crypto.createDecipheriv('aes-128-gcm', app.lengthEnKey, app.lengthEnIV);

                const aeadEncryptedResponseHeaderLength = buffer.subarray(0, 2)
                const aeadEncryptedResponseHeaderLengthTag = buffer.subarray(2, 18)


                decipher.setAuthTag(aeadEncryptedResponseHeaderLengthTag);
                const decryptedAEADHeaderLengthPayloadResult = Buffer.concat([decipher.update(aeadEncryptedResponseHeaderLength), decipher.final()])
                const decryptedResponseHeaderLength = decryptedAEADHeaderLengthPayloadResult.readUInt16BE(0) + 18


                const decipher2 = crypto.createDecipheriv('aes-128-gcm', app.payloadEnKey, app.payloadEnIV);
                const encryptedResponseHeaderBuffer = buffer.subarray(18, decryptedResponseHeaderLength)
                const encryptedResponseHeaderBufferTag = buffer.subarray(decryptedResponseHeaderLength, decryptedResponseHeaderLength + 16)


                decipher2.setAuthTag(encryptedResponseHeaderBufferTag);
                var header = Buffer.concat([decipher2.update(encryptedResponseHeaderBuffer), decipher2.final()])

                if (app._v !== header[0]) {
                    return onerror(app, `server response v doesn't match, expect ${app._v} but got ${header[0]}`, 1);
                }
                app._isHeaderRecv = true;
                if (!app._adBuf)
                    return onerror(app, 'fail to read _adBuf', 1);
                return app._adBuf.put(buffer.subarray(decryptedResponseHeaderLength + 16 + header[3]), app);
            }
        } catch (error) {
            return onerror(app, `unable to authenticate server response data: ${error}`)
        }
    }
    if (!app._adBuf)
        return onerror(app, 'fail to read _adBuf', 1);
    return app._adBuf.put(buffer, app);
}

function DecodeResponseBody(chunk, app) {
    if ([consts.SECURITY_TYPE_AES_128_GCM, consts.SECURITY_TYPE_CHACHA20_POLY1305].includes(app._security)) {
        const data = common.decrypt(chunk.subarray(2), app);
        if (data == null) {
            return onerror(app, `fail to decrypt data chunk`, 1);
        }
        app.user.bytesWrit += data.length
        if (app.localMessage)
            return app.localMessage(data);
    }
    app.user.bytesWrit += chunk.length - 2
    if (app.localMessage)
        return app.localMessage(chunk.subarray(2));
}

// =================================================  functions  

function resolveChunk(chunk) {
    let _chunk = chunk;
    if ([consts.SECURITY_TYPE_AES_128_GCM, consts.SECURITY_TYPE_CHACHA20_POLY1305].includes(this._security)) {
        _chunk = common.encrypt(_chunk, this)
    }
    if (this._option >= 0x01) {
        let _len = _chunk.length;
        var pad = 0
        if (this._option >= 0x05) {
            if (this._option >= 0x08) {
                const padmask = this._chunkLenEncMaskGenerator.nextBytes(2).readUInt16BE(0);
                pad = (padmask % 64)
            }
            const mask = this._chunkLenEncMaskGenerator.nextBytes(2).readUInt16BE(0);
            _len = mask ^ (_len + pad);
        }
        if (pad == 0)
            _chunk = Buffer.concat([common.ntb(_len), _chunk]);
        else
            _chunk = Buffer.concat([common.ntb(_len), _chunk, crypto.randomBytes(pad)]);
    }
    return _chunk
}

function onReceivingLength(buffer, app) {
    var len = buffer.length
    if (len < 2) {
        return;
    }
    if (app._option >= 0x01) {
        len = buffer.readUInt16BE(0);
        if (app._option >= 0x05 && app._chunkLenDecMaskGenerator) {
            var pad = 0
            if (app._option >= 0x08) {
                const padmask = app._chunkLenDecMaskGenerator.nextBytes(2).readUInt16BE(0);
                pad = (padmask % 64)
            }
            app.paddingLenght = pad
            const mask = app._chunkLenDecMaskGenerator.nextBytes(2).readUInt16BE(0);
            len = (mask ^ len);
        }
        len += 2;
    }
    return len
}

function getAddrType(host) {
    if (net.isIPv4(host)) {
        return ATYP_V4;
    }
    if (net.isIPv6(host)) {
        return ATYP_V6;
    }
    return ATYP_DOMAIN;
}
function getRandomInt(min, max) {
    min = Math.ceil(min);
    max = Math.ceil(max);
    const random = crypto.randomBytes(1)[0] / (0xff + 1e-13);
    return Math.floor(random * (max - min + 1) + min);
}

module.exports = init