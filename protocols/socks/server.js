'use strict'

const net = require('net'),
	DNS = require('dns'),
	utils = require('../../core/utils')
function init(data, remoteProtocol) {
	function auth(username, password) {
		for (const i of data.users) {
			if (username === i.user && password === i.pass) {
				return true;
			}
		}
	}
	const server = net.createServer();
	localsocket(auth, remoteProtocol, server)
	return server
}


const SOCKS_VERSION5 = 5,
	SOCKS_VERSION4 = 4;
/*
 * Authentication methods
 ************************
 * o  X'00' NO AUTHENTICATION REQUIRED
 * o  X'01' GSSAPI
 * o  X'02' USERNAME/PASSWORD
 * o  X'03' to X'7F' IANA ASSIGNED
 * o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
 * o  X'FF' NO ACCEPTABLE METHODS
 */
const AUTHENTICATION = {
	NOAUTH: 0x00,
	GSSAPI: 0x01,
	USERPASS: 0x02,
	NONE: 0xFF
};
/*
 * o  CMD
 *    o  CONNECT X'01'
 *    o  BIND X'02'
 *    o  UDP ASSOCIATE X'03'
 */
const REQUEST_CMD = {
	CONNECT: 0x01,
	BIND: 0x02,
	UDP_ASSOCIATE: 0x03
};
/*

 */
const SOCKS_REPLY = {
	SUCCEEDED: 0x00,
	SERVER_FAILURE: 0x01,
	NOT_ALLOWED: 0X02,
	NETWORK_UNREACHABLE: 0X03,
	HOST_UNREACHABLE: 0X04,
	CONNECTION_REFUSED: 0X05,
	TTL_EXPIRED: 0X06,
	COMMAND_NOT_SUPPORTED: 0X07,
	ADDR_NOT_SUPPORTED: 0X08,
};
/*
 * o  ATYP   address type of following address
 *    o  IP V4 address: X'01'
 *    o  DOMAINNAME: X'03'
 *    o  IP V6 address: X'04'
 */
const ATYP = {
	IP_V4: 0x01,
	DNS: 0x03,
	IP_V6: 0x04
};


//CMD reply
const _005B = Buffer.from([0x00, 0x5b]),//?
	_0101 = Buffer.from([0x01, 0x01]),//auth failed
	_0501 = Buffer.from([0x05, 0x01]),//general SOCKS server failure
	_0507 = Buffer.from([0x05, 0x01]),//Command not supported
	_0100 = Buffer.from([0x01, 0x00]);//auth succeeded


const Address = {
	read: function (buffer, offset) {//offset : offset of ATYP in buffer
		if (buffer[offset] == ATYP.IP_V4) {
			return `${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}.${buffer[offset + 4]}`;
		} else if (buffer[offset] == ATYP.DNS) {
			return buffer.toString('utf8', offset + 2, offset + 2 + buffer[offset + 1]);
		} else if (buffer[offset] == ATYP.IP_V6) {
			let h = [...buffer.slice(offset + 1, offset + 1 + 16)].map(num => num.toString(16).padStart(2, '0'));//to hex address
			//divide every 2 bytes into groups
			return `${h[0]}${h[1]}:${h[2]}${h[3]}:${h[4]}${h[5]}:${h[6]}${h[7]}:${h[8]}${h[9]}:${h[10]}${h[11]}:${h[12]}${h[13]}:${h[14]}${h[15]}`;
		}
	},
	//size of byteLength in buffer
	sizeOf: function (buffer, offset) {
		if (buffer[offset] == ATYP.IP_V4) {
			return 4;
		} else if (buffer[offset] == ATYP.DNS) {
			return buffer[offset + 1];
		} else if (buffer[offset] == ATYP.IP_V6) {
			return 16;
		}
	}
},
	Port = {
		read: function (buffer, offset) {//offset : offset of ATYP in buffer
			if (buffer[offset] == ATYP.IP_V4) {
				return buffer.readUInt16BE(8);
			} else if (buffer[offset] == ATYP.DNS) {
				return buffer.readUInt16BE(5 + buffer[offset + 1]);
			} else if (buffer[offset] == ATYP.IP_V6) {
				return buffer.readUInt16BE(20);
			}
		},
	};

/*
options:
	the same as net.Server options
*/

function localsocket(auth, remote, server) {
	server.on('connection', socket => {
		socket.once('data', chunk => {
			_handshake(socket, chunk);
		})
	});
	const socks5 = {
		authMethodsList: new Set([AUTHENTICATION.NOAUTH]),
		authConf: {
			userpass: new Map(),
		},
		authFunc: new Map([
			[AUTHENTICATION.USERPASS, _socks5UserPassAuth],
			[AUTHENTICATION.NOAUTH, _socks5NoAuth],
		]),
	};
	function _handshake4(socket, chunk) {// SOCKS4/4a
		let cmd = chunk[1],
			address,
			port,
			uid;

		port = chunk.readUInt16BE(2);

		// SOCKS4a
		if ((chunk[4] === 0 && chunk[5] === chunk[6] === 0) && (chunk[7] !== 0)) {
			var it = 0;

			uid = '';
			for (it = 0; it < 1024; it++) {
				uid += chunk[8 + it];
				if (chunk[8 + it] === 0x00)
					break;
			}
			address = '';
			if (chunk[8 + it] === 0x00) {
				for (it++; it < 2048; it++) {
					address += chunk[8 + it];
					if (chunk[8 + it] === 0x00)
						break;
				}
			}
			if (chunk[8 + it] === 0x00) {
				// DNS lookup
				DNS.lookup(address, (err, ip, family) => {
					if (err) {
						socket.end(_005B);
						socket.emit('socks_error', err);
						return;
					} else {
						socket.socksAddress = ip;
						socket.socksPort = port;

						if (cmd == REQUEST_CMD.CONNECT) {
							remote(address, port, 1, _CMD_REPLY4.bind(socket, SOCKS_REPLY.SUCCEEDED), socket)
						} else {
							socket.end(_005B);
							return;
						}
					}
				});
			} else {
				socket.end(_005B);
				return;
			}
		} else {
			// SOCKS4
			address = `${chunk[4]}.${chunk[5]}.${chunk[6]}.${chunk[7]}`;

			uid = '';
			for (it = 0; it < 1024; it++) {
				uid += chunk[8 + it];
				if (chunk[8 + it] == 0x00)
					break;
			}

			socket.socksAddress = address;
			socket.socksPort = port;

			if (cmd == REQUEST_CMD.CONNECT) {
				remote(address, port, 1, _CMD_REPLY4.bind(socket, SOCKS_REPLY.SUCCEEDED), socket)
			} else {
				socket.end(_005B);
				return;
			}
		}
	}
	function _handshake(socket, chunk) {
		if (chunk[0] != SOCKS_VERSION5) {
			if (chunk[0] == SOCKS_VERSION4)
				return _handshake4(socket, chunk)
			return socket.end();
		}
		let method_count = 0;

		// Number of authentication methods
		method_count = chunk[1];

		if (chunk.byteLength < method_count + 2) {
			socket.end();
			onerror('socks5 handshake error: too short chunk', 1);
			return;
		}

		let availableAuthMethods = [];
		// i starts on 2, since we've read chunk 0 & 1 already
		for (let i = 2; i < method_count + 2; i++) {
			if (socks5.authMethodsList.has(chunk[i])) {
				availableAuthMethods.push(chunk[i]);
			}
		}

		let resp = Buffer.from([
			SOCKS_VERSION5,//response version 5
			availableAuthMethods[0]//select the first auth method
		]);
		let authFunc = socks5.authFunc.get(resp[1]);

		if (availableAuthMethods.length === 0 || !authFunc) {//no available auth method
			resp[1] = AUTHENTICATION.NONE;
			socket.end(resp);
			onerror('unsupported authentication method', 1);
			return;
		}

		// auth
		socket.once('data', chunk => {
			authFunc(socket, chunk);
		});

		socket.write(resp);//socks5 auth response
	}
	function _socks5UserPassAuth(socket, chunk) {
		let username, password;
		// Wrong version!
		if (chunk[0] !== 1) { // MUST be 1
			socket.end(_0101);
			onerror(`socks5 handleAuthRequest: wrong socks version: ${chunk[0]}`, 1);
			return;
		}

		try {
			let na = [], pa = [], ni, pi;
			for (ni = 2; ni < (2 + chunk[1]); ni++) na.push(chunk[ni]); username = Buffer.from(na).toString('utf8');
			for (pi = ni + 1; pi < (ni + 1 + chunk[ni]); pi++) pa.push(chunk[pi]); password = Buffer.from(pa).toString('utf8');
		} catch (e) {
			socket.end(_0101);
			onerror(`socks5 handleAuthRequest: username/password ${e}`, 1);
			return;
		}

		// check user:pass
		let users = socks5.authConf.userpass;
		if (users && users.has(username) && users.get(username) === password) {
			socket.once('data', chunk => {
				_socks5HandleRequest(socket, chunk);
			});
			socket.write(_0100);//success
		} else {
			setTimeout(() => {
				socket.end(_0101);//failed
				onerror(`socks5 handleConnRequest: auth failed`, 1);
			}, Math.floor(Math.random() * 90 + 3));
			return;
		}
	}
	function _socks5NoAuth(socket, chunk) {
		_socks5HandleRequest(socket, chunk);
	}
	function _socks5HandleRequest(socket, chunk) {//the chunk is the cmd request head
		let cmd = chunk[1],//command
			address,
			port;
		// offset = 3;
		if (cmd != REQUEST_CMD.CONNECT && cmd != REQUEST_CMD.UDP_ASSOCIATE) {
			_CMD_REPLY5.call(socket, SOCKS_REPLY.COMMAND_NOT_SUPPORTED);
			return;
		}

		try {
			address = Address.read(chunk, 3);
			port = Port.read(chunk, 3);
		} catch (e) {
			socket.end();
			onerror(e, 1);
			return;
		}

		if (cmd === REQUEST_CMD.CONNECT) {
			remote(address, port, 1, _CMD_REPLY5.bind(socket, SOCKS_REPLY.SUCCEEDED), socket)
		} else if (cmd === REQUEST_CMD.UDP_ASSOCIATE) {
			UDP(socket, _CMD_REPLY5.bind(socket, SOCKS_REPLY.SUCCEEDED), utils.UDPBind, remote)
		} else {
			socket.end(_0507);
			return;
		}
	}
}
function UDP(socket, CMD_REPLY, local, remote) {
	var finalClientAddress
	var finalClientPort
	var relaySocket
	const remoteConncetion = remote(socket.localAddress, socket.localPort, 3,
		function () {
			relaySocket = local(onlocalconnect, onclient, onclose) 
		},
		onremote, onclose)
	function onlocalconnect(host, port) {
		if (host && port) {
			CMD_REPLY(host, port);
		} else if (this && typeof this.address == "function") {
			const ad = this.address()
			CMD_REPLY(ad.address, ad.port);
		}
	}
	function onclose() {
		remoteConncetion && remoteConncetion.close()
		relaySocket && relaySocket.close()
		socket.destroy()
	}
	function onremote(msg, info) {
		let head = setHeaderReplyToIP(info.address, info.port);
		head[0] = 0x00;
		relaySocket.message(Buffer.concat([head, msg]), finalClientPort, finalClientAddress);
	}
	function onclient(msg, info) {
		finalClientAddress = info.address;
		finalClientPort = info.port;
		let headLength = validateSocks5UDPHead(msg);
		if (!headLength)
			return;
		remoteConncetion.message(msg.slice(headLength), Port.read(msg, 3), Address.read(msg, 3));
	}
}

// ======================================= utils
const _0000 = Buffer.from([0, 0, 0, 0])
// const _00 = Buffer.from([0, 0]);

function setHeaderReplyToIP(addr, port) {
	let resp = [0x05, 0x00, 0x00];
	if (!addr) {
		resp.push(0x01, ..._0000);
	} else if (net.isIPv4(addr)) {
		resp.push(0x01, ...utils.ip4toBuffer(addr));
	} else if (net.isIPv6(addr)) {
		resp.push(0x04, ...utils.ip6toBuffer(addr));
	} else {
		addr = Buffer.from(addr);
		if (addr.byteLength > 255)
			onerror('too long domain name', 1);
		resp.push(0x03, addr.byteLength, ...addr);
	}
	if (!port) resp.push(0, 0);//default:0
	else {
		resp.push(port >>> 8, port & 0xFF);
	}
	return Buffer.from(resp);
}

function _CMD_REPLY5(REP, addr, port) {//'this' is the socket
	if (this.CMD_REPLIED || !this.writable) return false;//prevent it from replying twice
	// creating response
	if (REP) {//something wrong
		this.end(Buffer.from([0x05, REP, 0x00]));
	} else {
		this.write(setHeaderReplyToIP(addr, port));
	}
	this.CMD_REPLIED = true;
	return true;
}

function _CMD_REPLY4() {//'this' is the socket
	if (this.CMD_REPLIED) return;
	// creating response
	let resp = Buffer.allocUnsafe(8);

	// write response header
	resp[0] = 0x00;
	resp[1] = 0x5a;

	// port
	resp.writeUInt16BE(this.socksPort, 2);

	// ip
	let ips = this.socksAddress.split('.');
	resp.writeUInt8(parseInt(ips[0]), 4);
	resp.writeUInt8(parseInt(ips[1]), 5);
	resp.writeUInt8(parseInt(ips[2]), 6);
	resp.writeUInt8(parseInt(ips[3]), 7);

	this.write(resp);
	this.CMD_REPLIED = true;
}

function validateSocks5UDPHead(buf) {
	if (buf[0] !== 0 || buf[1] !== 0) return false;
	let minLength = 6;//data length without addr
	if (buf[3] === 0x01) { minLength += 4; }
	else if (buf[3] === 0x03) { minLength += buf[4]; }
	else if (buf[3] === 0x04) { minLength += 16; }
	else return false;
	if (buf.byteLength < minLength) return false;
	return minLength;
}


function onerror(error, ind) {
	log(error, ind)
}



module.exports = init
