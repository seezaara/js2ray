"use strict";
const common = require("./common")
const validator = require("./validator")
const AdvancedBuffer = require("./advanced-buffer")
const kdf = require("./kdf")
const consts = require("./consts")
const crypto = require("crypto");

const utils = require('../../core/utils');


const ATYP_V4 = 0x01;
const ATYP_DOMAIN = 0x02;
const ATYP_V6 = 0x03;

function init(data, remoteProtocol) {
    var checkuser = validator.init(data).check
    return function (socket, ip) {
        socket.app = {}
        socket.app.ip = ip
        socket.app._staging = Buffer.alloc(0)
        socket.app._isConnecting = false;
        socket.app._isHeaderSent = false;
        socket.app._isHeaderRecv = false;
        socket.app._cipherNonce = 0;
        socket.app._decipherNonce = 0;

        socket.app._adBuf = new AdvancedBuffer({ getPacketLength: onReceivingLength });
        socket.app._adBuf.on('data', DecodeRequestBody);

        return {
            message: DecodeRequestHeader.bind(socket, remoteProtocol, EncodeResponseBody.bind(socket), socket.localClose, checkuser),
            close: function () {
                onclose(socket.app);
                delete socket.app
            },
        }
    }
}




function DecodeRequestHeader(remoteProtocol, onRemoteMessage, onRemoteClose, checkuser, buffer) {
    const app = this.app
    if (app) {
        if (!app._isHeaderRecv) {
            if (app._isConnecting) {
                if (!buffer || !app._staging)
                    return
                app._staging = Buffer.concat([app._staging, buffer]);
                return;
            }

            if (buffer.length < 16) {
                return onerror(app, `fail to parse request header: ${buffer.toString("hex")}`, 1);
            }

            const reqCommand = Buffer.from(buffer.subarray(16));
            var aeadUser = checkuser(buffer.subarray(0, 16), true)
            if (aeadUser == undefined) {
                var dataoffset = 16
                const user = checkuser(buffer.subarray(0, 16).toString("hex"));
                if (user == undefined)
                    return onerror(app, `cannot find ${buffer.subarray(0, 16).toString("hex")} in cache, maybe a wrong auth info`, 1);
                var ts = user[1]
                aeadUser = user[0]
                var decipher = crypto.createDecipheriv('aes-128-cfb', aeadUser.id.cmdKey,
                    common.hash('md5', Buffer.concat([ts, ts, ts, ts])));
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
                    return onerror(app, `AEAD read failed`, 1)
                }
                app.user = aeadUser
                app._isAEADRequest = true
            } else {
                return onerror(app, `invalid user`, 1);
            }
            if (aeadUser.deactive)
                return

            if (aeadUser.traffic != 0 && common.trafficlimit(aeadUser)) {
                return onerror(app, `maximum traffic ${aeadUser.traffic / 1024 / 1024}MB (bytesRead:${aeadUser.bytesRead},bytesWrit:${aeadUser.bytesWrit}) used by user ${aeadUser.id.UUID.toString("hex")}`, 1)
            }
            if (aeadUser.expire && aeadUser.expire < new Date().getTime()) {
                return onerror(app, `expire user ${aeadUser.id.UUID.toString("hex")}`, 1)
            }
            if (aeadUser.ipCount != 0 && common.iplimit(app.ip, aeadUser))
                return onerror(app, `maximum ip used by user ${aeadUser.id.UUID.toString("hex")}`, 1)

            if (reqCommand.length < 41) {
                return onerror(app, `request command is too short: ${reqCommand.length}bytes, command=${reqCommand.toString('hex')}`, 1);
            }

            const reqHeader = decipher.subarray(0, 41);
            const ver = reqHeader[0];

            if (ver !== 0x01) {
                return onerror(app, `invalid version number: ${ver}`, 1);
            }

            app._dataDecIV = reqHeader.subarray(1, 17);
            app._dataDecKey = reqHeader.subarray(17, 33);
            if (app._isAEADRequest) {
                app._dataEncIV = common.hash('sha256', app._dataDecIV).subarray(0, 16);
                app._dataEncKey = common.hash('sha256', app._dataDecKey).subarray(0, 16);
                app.lengthEnKey = kdf.KDF16(app._dataEncKey, consts.KDFSaltConstAEADRespHeaderLenKey)
                app.lengthEnIV = kdf.KDF(app._dataEncIV, consts.KDFSaltConstAEADRespHeaderLenIV).subarray(0, 12)
                app.payloadEnKey = kdf.KDF16(app._dataEncKey, consts.KDFSaltConstAEADRespHeaderPayloadKey)
                app.payloadEnIV = kdf.KDF(app._dataEncIV, consts.KDFSaltConstAEADRespHeaderPayloadIV).subarray(0, 12)
            } else {
                app._dataEncIV = common.hash('md5', app._dataDecIV);
                app._dataEncKey = common.hash('md5', app._dataDecKey);
            }


            app._chunkLenDecMaskGenerator = common.shake128(app._dataDecIV);
            app._chunkLenEncMaskGenerator = common.shake128(app._dataEncIV);

            app._responseHeader = reqHeader[33];
            app._option = reqHeader[34];
            const paddingLen = reqHeader[35] >> 4;
            // 2 'auto'
            // 3 'aes-128-gcm'
            // 4 'chacha20-poly1305'
            // 5 'none'
            // 6 'zero'
            const securityType = reqHeader[35] & 0x0F;
            app._security = securityType;
            if (!(aeadUser.security == 2 || aeadUser.security == undefined || securityType == 2) && securityType != aeadUser.security) {
                return onerror(app, `not match securety type`, 1);
            }
            if (securityType == consts.SECURITY_TYPE_CHACHA20_POLY1305) {
                app._dataEncKeyForChaCha20 = common.createChacha20Poly1305Key(app._dataEncKey);
                app._dataDecKeyForChaCha20 = common.createChacha20Poly1305Key(app._dataDecKey);
            }
            //===========
            let offset = 40;
            var cmd = reqHeader[37];
            if (![0x01, 0x02].includes(cmd)) {
                return onerror(app, `unsupported cmd: ${cmd}`, 1);
            }
            app._cmd = cmd;

            if (cmd === 0x03) {
                return
                const socket = this

                // Invoke remoteProtocol with cmd=3, setting up UDP relay
                app.remote = remoteProtocol(
                    '0.0.0.0', // target unused
                    0,
                    3,
                    () => {
                        app._isHeaderRecv = true;
                        app._isConnecting = false;
                        app._staging = null;
                    },
                    (chunk) => {
                        console.log(2000)
                        var buffer = encodeMuxUDPResponse(app.sessionIn, app.sessionID, chunk)

                        buffer = buffer.subarray(2)

                        const frameLength = buffer.readUInt16BE(0);       // not used directly here
                        const sessionStatus = buffer[4];
                        const option = buffer[5];
                        var offset = 6;
                        if ((option & 0x01) === 0 || sessionStatus !== 0x02)
                            return console.log(2000, option, sessionStatus);
                        ;
                        var id = buffer.readUInt16BE(2);

                        console.log({
                            frameLength,
                            sessionStatus,
                            option,
                            offset,
                            id,
                        });



                        socket.localMessage(encodeMuxUDPResponse(app.sessionIn, app.sessionID, chunk))
                    },
                    onRemoteClose
                );
                return; // done with header stage
            }
            else {
                var port = reqHeader.readUInt16BE(38);
                var addrType = reqHeader[40];
                var addr = null;
                if (addrType === ATYP_V4) {
                    if (reqCommand.length < 45) {
                        return onerror(app, `request command is too short ${reqCommand.length}bytes to get ipv4, command=${reqCommand.toString('hex')}`, 1);
                    }

                    addr = decipher.subarray(41, 45);
                    offset += 4;
                } else if (addrType === ATYP_V6) {
                    if (reqCommand.length < 57) {
                        return onerror(app, `request command is too short: ${reqCommand.length}bytes to get ipv6, command=${reqCommand.toString('hex')}`, 1);
                    }

                    addr = decipher.subarray(41, 57);
                    offset += 16;
                } else if (addrType === ATYP_DOMAIN) {
                    if (reqCommand.length < 42) {
                        return onerror(app, `request command is too short: ${reqCommand.length}bytes to get host name, command=${reqCommand.toString('hex')}`, 1);
                    }

                    const addrLen = decipher.subarray(41, 42)[0];

                    if (reqCommand.length < 42 + addrLen) {
                        return onerror(app, `request command is too short: ${reqCommand.length}bytes, command=${reqCommand.toString('hex')}`, 1);
                    }

                    addr = decipher.subarray(42, 42 + addrLen);
                    offset += 1 + addrLen;
                } else {
                    return onerror(app, `unknown address type: ${addrType}, command=${reqHeader.toString('hex')}`, 1);
                }
            }

            if (reqCommand.length < offset + paddingLen + 4) {
                return onerror(app, `request command is too short: ${reqCommand.length}bytes to get padding and f, command=${reqCommand.toString('hex')}`, 1);
            }

            const padding = decipher.subarray(offset, offset + paddingLen);
            offset += paddingLen;
            const f = decipher.subarray(offset, offset + 4);

            const plainReqHeader = Buffer.from([...reqHeader.subarray(0, 41), ...(addrType === ATYP_DOMAIN ? [addr.length] : []), ...addr, ...padding]);

            if (common.fnv1a(plainReqHeader).equals(f)) {
                return onerror(app, 'fail to verify request command', 1);
            }
            const data = buffer.subarray(dataoffset + plainReqHeader.length + 4);
            app._isConnecting = true;
            app.remote = remoteProtocol(
                addrType === ATYP_DOMAIN ? addr.toString() : utils.iptoString(addr),
                port,
                cmd,
                function () {
                    if (!app._adBuf)
                        return
                    app._adBuf.put(Buffer.concat([data, app._staging]), app);
                    app._isHeaderRecv = true;
                    app._isConnecting = false;
                    app._staging = null;
                },
                onRemoteMessage,
                onRemoteClose
            )
        } else {
            if (app.user.deactive)
                return
            if (app.user.traffic != 0 && common.trafficlimit(app.user))
                return onerror(app, `maximum traffic ${app.user.traffic / 1024 / 1024}MB (bytesRead:${app.user.bytesRead},bytesWrit:${app.user.bytesWrit}) used by user ${app.user.id.UUID.toString("hex")}`, 1);
            if (app.user.expire && app.user.expire < new Date().getTime()) {
                return onerror(app, `expire user ${app.user.id.UUID.toString("hex")}`, 1)
            }
            if (common.update_ip(app.ip, app.user))
                return onerror(app, `maximum ip used by user ${app.user.id.UUID.toString("hex")}`, 1)
            if (!app._adBuf)
                return onerror(app, 'fail to read _adBuf', 1);
            // if (app._cmd == 3) {
            //     return decodeMuxUDPRequest(buffer, app)
            // }
            app._adBuf.put(buffer, app);
        }
    }
}

function decodeMuxUDPRequest(buffer, app) {
    if (buffer.length < 9) return null;
    app.sessionIn = buffer.subarray(0, 2)

    buffer = buffer.subarray(2)
    // const frameLength = buffer.readUInt16BE(0);       // not used directly here
    const sessionStatus = buffer[4];
    const option = buffer[5];
    var offset = 6;
    const network = buffer[offset++];
    if ((option & 0x01) === 0 || sessionStatus !== 0x02 || network != 2)
        return;
    app.sessionID = buffer.readUInt16BE(2);

    let address, port;
    port = buffer.readUInt16BE(offset);
    offset += 2;

    const atyp = buffer[offset++];
    if (atyp === 0x01) { // IPv4
        address = [...buffer.slice(offset, offset + 4)].join('.');
        offset += 4;
    } else if (atyp === 0x03) { // Domain
        const domainLen = buffer[offset++];
        address = buffer.slice(offset, offset + domainLen).toString();
        offset += domainLen;
    } else if (atyp === 0x04) { // IPv6
        address = buffer.slice(offset, offset + 16).toString('hex').match(/.{1,4}/g).join(':');
        offset += 16;
    } else {
        throw new Error("Unknown ATYP: " + atyp);
    }

    offset += 2;
    return app.remote.message(buffer.slice(offset), port, address);
}

function encodeMuxUDPResponse(sessionIn, sessionID, payloadBuffer) {
    const header = Buffer.alloc(6); // 2 length + 2 sessionID + 1 status + 1 option

    // Will fill length later
    header.writeUInt16BE(0, 0); // Placeholder for length 
    header.writeUInt16BE(sessionID, 2); // Session ID
    header[4] = 0x02; // SessionStatusKeep
    header[5] = 0x01; // OptionData

    const frame = Buffer.concat([sessionIn, header, payloadBuffer]);

    // Now write real length into first 2 bytes (excluding length bytes themselves) 

    frame.writeUInt16BE(frame.length - 2, 0);

    return frame;
}


function EncodeResponseHeader(app) {
    var outBuffer = Buffer.from([app._responseHeader, 0x00, 0x00, 0x00])
    try {
        if (!app._isAEADRequest) {
            var encryptionWriter = crypto.createCipheriv('aes-128-cfb', app._dataEncKey, app._dataEncIV);
            return encryptionWriter.update(outBuffer);
        } else {
            const aeadResponseHeaderLengthEncryptionBuffer = Buffer.alloc(2);
            aeadResponseHeaderLengthEncryptionBuffer.writeUInt16BE(outBuffer.length)

            const cipher = crypto.createCipheriv('aes-128-gcm', app.lengthEnKey, app.lengthEnIV);
            var AEADEncryptedLength = Buffer.concat([cipher.update(aeadResponseHeaderLengthEncryptionBuffer), cipher.final(), cipher.getAuthTag()])

            const cipher2 = crypto.createCipheriv('aes-128-gcm', app.payloadEnKey, app.payloadEnIV);

            var aeadEncryptedHeaderPayload = Buffer.concat([cipher2.update(outBuffer), cipher2.final(), cipher2.getAuthTag()])
            return Buffer.concat([AEADEncryptedLength, aeadEncryptedHeaderPayload])
        }
    } catch (error) {
        onerror(app, error)
    }
}

function EncodeResponseBody(buffer) {
    const app = this.app
    if (app) {
        if (!app._isHeaderSent) {
            app._isHeaderSent = true;
            const header = EncodeResponseHeader(app)
            app.user.bytesRead += buffer.length
            const chunks = common.getChunks(buffer, 0x3fff).map(resolveChunk.bind(app));
            // this.localMessage(header)
            this.localMessage(Buffer.concat([header, ...chunks]))
        } else {
            app.user.bytesRead += buffer.length
            const chunks = common.getChunks(buffer, 0x3fff).map(resolveChunk.bind(app));
            this.localMessage(Buffer.concat(chunks))
        }
    }
}
function DecodeRequestBody(chunk, app) {
    if ([consts.SECURITY_TYPE_AES_128_GCM, consts.SECURITY_TYPE_CHACHA20_POLY1305].includes(app._security)) {
        const data = common.decrypt(chunk.subarray(2, chunk.length - app.paddingLenght), app);
        if (data == null) {
            return onerror(app, "fail to decrypt data chunk", 1);
        }
        app.user.bytesWrit += data.length
        if (app.remote)
            return app.remote.message(data);
    }
    app.user.bytesWrit += chunk.length - 2

    if (app.remote)
        return app.remote.message(chunk.subarray(2));
}

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
        if (app._option >= 0x05) {
            var pad = 0
            if (app._option >= 0x08 && app._chunkLenDecMaskGenerator) {
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

function onerror(app, error, ind) {
    log(error, ind)
    onclose(app);
}

function onclose(app) {
    if (!app)
        return
    if (app.remote)
        app.remote.close()
    app.remote = null

    app._isConnecting = false;
    app._isHeaderSent = false;
    app._isHeaderRecv = false;
    if (app._adBuf)
        app._adBuf.clear();
    app._adBuf = null;
    app._option = null
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
}


module.exports = init 