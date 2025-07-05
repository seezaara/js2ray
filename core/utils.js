
const net = require('net')
const dgram = require('dgram')
const ipv4Regex = /^(\d{1,3}\.){3,3}\d{1,3}$/;
// const ipv6Regex = /^(::)?(((\d{1,3}\.){3}(\d{1,3}){1})?([0-9a-f]){0,4}:{0,2}){1,8}(::)?$/i; // so slow

function iptoBuffer(ip, buff, offset) {
    if (ipv4Regex.test(ip)) {
        return ip4toBuffer(ip, buff, offset)
    } else if (net.isIPv6(ip)) {
        return ip6toBuffer(ip, buff, offset)
    }
};
function ip6toBuffer(ip = "", buff, offset) {
    offset = ~~offset;
    let result;

    const sections = ip.split(':', 8);

    let i;
    for (i = 0; i < sections.length; i++) {
        const isv4 = ipv4Regex.test(sections[i]);
        let v4Buffer;

        if (isv4) {
            v4Buffer = this.toBuffer(sections[i]);
            sections[i] = v4Buffer.subarray(0, 2).toString('hex');
        }

        if (v4Buffer && ++i < 8) {
            sections.splice(i, 0, v4Buffer.subarray(2, 4).toString('hex'));
        }
    }

    if (sections[0] === '') {
        while (sections.length < 8) sections.unshift('0');
    } else if (sections[sections.length - 1] === '') {
        while (sections.length < 8) sections.push('0');
    } else if (sections.length < 8) {
        for (i = 0; i < sections.length && sections[i] !== ''; i++);
        const argv = [i, 1];
        for (i = 9 - sections.length; i > 0; i--) {
            argv.push('0');
        }
        sections.splice(...argv);
    }

    result = buff || Buffer.alloc(offset + 16);
    for (i = 0; i < sections.length; i++) {
        const word = parseInt(sections[i], 16);
        result[offset++] = (word >> 8) & 0xff;
        result[offset++] = word & 0xff;
    }

    if (!result) {
        throw Error(`Invalid ip address: ${ip}`);
    }

    return result;
};
function ip4toBuffer(ip = "", buff, offset) {
    offset = ~~offset;
    let result;

    result = buff || Buffer.alloc(offset + 4);
    ip.split(/\./g).map((byte) => {
        result[offset++] = parseInt(byte, 10) & 0xff;
    });

    if (!result) {
        throw Error(`Invalid ip address: ${ip}`);
    }

    return result;
};

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
function int2ip(ipInt) {
    return ((ipInt >>> 24) + '.' + (ipInt >> 16 & 255) + '.' + (ipInt >> 8 & 255) + '.' + (ipInt & 255));
}
function ip2int(ip) {
    return ip.split('.').reduce(function (ipInt, octet) { return (ipInt << 8) + parseInt(octet, 10) }, 0) >>> 0;
}

function UDPBind(onconnect, onmessage, onclose, v6) {
    // =====================
    if (typeof onmessage == "object") {
        const pipeSocket = onmessage
        onmessage = pipeSocket.write.bind(pipeSocket)
        onclose = pipeSocket.destroy.bind(pipeSocket)
        pipeSocket.on("error", close)
        pipeSocket.on("close", close)
        pipeSocket.on("data", message)
    }

    var dgramsocket
    if (v6) {
        dgramsocket = dgram.createSocket('udp6');
    } else
        dgramsocket = dgram.createSocket('udp4');

 
    function close() { 
        if (dgramsocket == null)
            return
        dgramsocket.close()
        dgramsocket = null
    }
    function message(buffer, p, h) { 
        if (dgramsocket == null || !p || p <= 0 || p >= 65536)
            return
        dgramsocket.send(buffer, p, h)
    }
    if (dgramsocket) {
        dgramsocket.on('error', close);
        dgramsocket.on('message', onmessage) 
        // =====================
        const timeout = setTimeout(close, 10000)
        dgramsocket.on('close', function () {
            onclose()
            dgramsocket = null
            clearTimeout(timeout)
        });
        dgramsocket.once('message', clearTimeout.bind(null, timeout));
        // =====================  
        dgramsocket.bind(onconnect);
    }
    else
        onclose()
    return {
        close,
        message,
    }
}
module.exports = {
    ip4toBuffer,
    ip6toBuffer,
    iptoString,
    iptoBuffer,
    int2ip,
    ip2int,
    UDPBind,
}
