'use strict'

const net = require('net')
const DNS = require('dns')
const utils = require('../../core/utils')

function init(data, remoteProtocol) {
	if (data.users?.length > 0)
		var userMap = new Map(data.users.map(u => [u.user, u.pass])); 
	const server = net.createServer();
	localsocket((username, password) => userMap.get(username) === password, remoteProtocol, server, data.users?.length > 0)
	return server;
}

const SOCKS_VERSION5 = 5,
	SOCKS_VERSION4 = 4;

const AUTHENTICATION = {
	NOAUTH: 0x00,
	USERPASS: 0x02,
	NONE: 0xFF
};

const REQUEST_CMD = {
	CONNECT: 0x01,
	BIND: 0x02,
	UDP_ASSOCIATE: 0x03
};

const SOCKS_REPLY = {
	SUCCEEDED: 0x00,
	COMMAND_NOT_SUPPORTED: 0x07,
};

const ATYP = {
	IP_V4: 0x01,
	DNS: 0x03,
	IP_V6: 0x04
};

const _005B = Buffer.from([0x00, 0x5b])
const _0101 = Buffer.from([0x01, 0x01])
const _0100 = Buffer.from([0x01, 0x00])
const _0507 = Buffer.from([0x05, 0x07])

const Address = {
	read: function (buffer, offset) {
		if (buffer[offset] == ATYP.IP_V4)
			return `${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}.${buffer[offset + 4]}`
		if (buffer[offset] == ATYP.DNS)
			return buffer.toString('utf8', offset + 2, offset + 2 + buffer[offset + 1])
		if (buffer[offset] == ATYP.IP_V6) {
			let h = [...buffer.slice(offset + 1, offset + 1 + 16)].map(num => num.toString(16).padStart(2, '0'))
			return `${h[0]}${h[1]}:${h[2]}${h[3]}:${h[4]}${h[5]}:${h[6]}${h[7]}:${h[8]}${h[9]}:${h[10]}${h[11]}:${h[12]}${h[13]}:${h[14]}${h[15]}`
		}
	},
	sizeOf: function (buffer, offset) {
		if (buffer[offset] == ATYP.IP_V4) return 4
		if (buffer[offset] == ATYP.DNS) return buffer[offset + 1]
		if (buffer[offset] == ATYP.IP_V6) return 16
	}
}
const Port = {
	read: function (buffer, offset) {
		if (buffer[offset] == ATYP.IP_V4) return buffer.readUInt16BE(8)
		if (buffer[offset] == ATYP.DNS) return buffer.readUInt16BE(5 + buffer[offset + 1])
		if (buffer[offset] == ATYP.IP_V6) return buffer.readUInt16BE(20)
	}
}

function localsocket(auth, remote, server, hasAuth) {
	server.on('connection', socket => {
		socket.once('data', chunk => {
			_handshake(socket, chunk);
		})
	})

	function _handshake4(socket, chunk) {
		const cmd = chunk[1]
		const port = chunk.readUInt16BE(2)
		let address, uid = ''
		if ((chunk[4] === 0 && chunk[5] === chunk[6] === 0) && chunk[7] !== 0) {
			let i = 0
			for (i = 8; i < 1024; i++) {
				if (chunk[i] === 0x00) break
				uid += chunk[i]
			}
			address = ''
			for (i++; i < 2048; i++) {
				if (chunk[i] === 0x00) break
				address += String.fromCharCode(chunk[i])
			}
			DNS.lookup(address, (err, ip) => {
				if (err) return socket.end(_005B)
				socket.socksAddress = ip
				socket.socksPort = port
				if (cmd === REQUEST_CMD.CONNECT) {
					remote(address, port, 1, _CMD_REPLY4.bind(socket, SOCKS_REPLY.SUCCEEDED), socket)
				} else socket.end(_005B)
			})
		} else {
			address = `${chunk[4]}.${chunk[5]}.${chunk[6]}.${chunk[7]}`
			for (let i = 8; i < 1024; i++) {
				if (chunk[i] === 0x00) break
				uid += chunk[i]
			}
			socket.socksAddress = address
			socket.socksPort = port
			if (cmd === REQUEST_CMD.CONNECT) {
				remote(address, port, 1, _CMD_REPLY4.bind(socket, SOCKS_REPLY.SUCCEEDED), socket)
			} else socket.end(_005B)
		}
	}

	function _handshake(socket, chunk) {
		if (chunk[0] !== SOCKS_VERSION5) {
			if (chunk[0] === SOCKS_VERSION4) return _handshake4(socket, chunk)
			return socket.end()
		}

		const methodCount = chunk[1]
		const clientMethods = [...chunk.slice(2, 2 + methodCount)]

		const selectedMethod = hasAuth ? AUTHENTICATION.USERPASS : AUTHENTICATION.NOAUTH

		if (!clientMethods.includes(selectedMethod)) {
			socket.end(Buffer.from([SOCKS_VERSION5, AUTHENTICATION.NONE]))
			return
		}

		socket.write(Buffer.from([SOCKS_VERSION5, selectedMethod]))

		if (selectedMethod === AUTHENTICATION.NOAUTH) {
			socket.once('data', chunk => _socks5HandleRequest(socket, chunk))
		} else {
			socket.once('data', chunk => {
				if (chunk[0] !== 1) return socket.end(_0101)
				try {
					const ulen = chunk[1]
					const username = chunk.slice(2, 2 + ulen).toString()
					const plen = chunk[2 + ulen]
					const password = chunk.slice(3 + ulen, 3 + ulen + plen).toString()
					if (auth(username, password)) {
						socket.write(_0100)
						socket.once('data', chunk => _socks5HandleRequest(socket, chunk))
					} else {
						setTimeout(() => socket.end(_0101), Math.random() * 90 + 3)
					}
				} catch (e) {
					socket.end(_0101)
				}
			})
		}
	}

	function _socks5HandleRequest(socket, chunk) {
		const cmd = chunk[1]
		if (![REQUEST_CMD.CONNECT, REQUEST_CMD.UDP_ASSOCIATE].includes(cmd)) {
			return _CMD_REPLY5.call(socket, SOCKS_REPLY.COMMAND_NOT_SUPPORTED)
		}
		let address, port
		try {
			address = Address.read(chunk, 3)
			port = Port.read(chunk, 3)
		} catch (e) {
			return socket.end()
		}

		if (cmd === REQUEST_CMD.CONNECT) {
			remote(address, port, 1, _CMD_REPLY5.bind(socket, SOCKS_REPLY.SUCCEEDED), socket)
		} else {
			UDP(socket, _CMD_REPLY5.bind(socket, SOCKS_REPLY.SUCCEEDED), utils.UDPBind, remote)
		}
	}
}

function UDP(socket, CMD_REPLY, local, remote) {
	let finalClientAddress, finalClientPort, relaySocket
	const remoteConn = remote(socket.localAddress, socket.localPort, 3,
		() => {
			relaySocket = local(onlocalconnect, onclient, onclose)
		}, onremote, onclose)

	function onlocalconnect(host, port) {
		CMD_REPLY(host ?? this.address().address, port ?? this.address().port)
	}

	function onclose() {
		remoteConn?.close()
		relaySocket?.close()
		socket.destroy()
	}

	function onremote(msg, info) {
		const head = setHeaderReplyToIP(info.address, info.port)
		head[0] = 0x00
		relaySocket.message(Buffer.concat([head, msg]), finalClientPort, finalClientAddress)
	}

	function onclient(msg, info) {
		finalClientAddress = info.address
		finalClientPort = info.port
		const headLen = validateSocks5UDPHead(msg)
		if (!headLen) return
		remoteConn.message(msg.slice(headLen), Port.read(msg, 3), Address.read(msg, 3))
	}
}

const _0000 = Buffer.from([0, 0, 0, 0])

function setHeaderReplyToIP(addr, port) {
	const res = [0x05, 0x00, 0x00]
	if (!addr) res.push(0x01, ..._0000)
	else if (net.isIPv4(addr)) res.push(0x01, ...utils.ip4toBuffer(addr))
	else if (net.isIPv6(addr)) res.push(0x04, ...utils.ip6toBuffer(addr))
	else {
		const b = Buffer.from(addr)
		res.push(0x03, b.length, ...b)
	}
	res.push(port >> 8, port & 0xFF)
	return Buffer.from(res)
}

function _CMD_REPLY5(REP, addr, port) {
	if (this.CMD_REPLIED || !this.writable) return false
	if (REP) this.end(Buffer.from([0x05, REP, 0x00]))
	else this.write(setHeaderReplyToIP(addr, port))
	this.CMD_REPLIED = true
	return true
}

function _CMD_REPLY4() {
	if (this.CMD_REPLIED) return
	const r = Buffer.allocUnsafe(8)
	r[0] = 0x00; r[1] = 0x5a
	r.writeUInt16BE(this.socksPort, 2)
	const ips = this.socksAddress.split('.')
	for (let i = 0; i < 4; i++) r[4 + i] = parseInt(ips[i])
	this.write(r)
	this.CMD_REPLIED = true
}

function validateSocks5UDPHead(buf) {
	if (buf[0] !== 0 || buf[1] !== 0) return false
	let len = 6
	if (buf[3] === 0x01) len += 4
	else if (buf[3] === 0x03) len += buf[4]
	else if (buf[3] === 0x04) len += 16
	else return false
	return buf.length >= len ? len : false
}

function onerror(error, ind) {
	log(error, ind)
}

module.exports = init
