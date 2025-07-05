const net = require('net');
const dgram = require('dgram');
const utils = require('../../core/utils');
const SmartBuffer = require('smart-buffer');

function init(data, remoteNetwork) {
	return function (address, port, cmd, localConnect, localMessage, localClose) {
		const network = data.networks.length == 1 ? data.networks[0] : data.networks[Math.floor(Math.random() * data.networks.length)]

		// ========================================== pipe 
		if (typeof localMessage == "object") {
			var socket = remoteNetwork(
				network.address,
				network.port,
				cmd,
				function () {
					onconnect(socket, address, port, function () {
						localConnect()
						localMessage.pipe(socket);
						socket.pipe(localMessage);
					})
				},
				null,
				null,
			)

			socket._buff = new SmartBuffer();
			socket._cmd = cmd;

			return
		} else {
			if (cmd == 1) {
				var socket = remoteNetwork(
					network.address,
					network.port,
					cmd,
					onconnected,
					null,
					localClose,
				)
				socket._buff = new SmartBuffer();
				socket._cmd = cmd;
				function onconnected() {
					onconnect(socket, address, port, function () {
						localConnect()
						socket.on('data', localMessage);
					})
				}
				const out = {
					message: socket.write.bind(socket),
					close: onclose.bind(null, socket)
				}
				return out
			} else {
				var socket = remoteNetwork(
					network.address,
					network.port,
					cmd,
					onconnected,
					null,
					localClose,
				)
				socket._buff = new SmartBuffer();
				socket._cmd = cmd;
				var udp = new dgram.Socket('udp4');
				function onconnected() {
					onconnect(socket, "0.0.0.0", 0, function (localhost, localport) {
						socket.localhost = localhost
						socket.localport = localport
						udp.on('message', function (msg) {
							let headLength = validateSocks5UDPHead(msg);
							if (!headLength)
								return;
							localMessage(msg.slice(headLength), parseUDPFrame(msg))
						});
						udp.on('error', localClose);
						udp.bind(localConnect)
					})
				}
				const out = {
					message: function (data, remoteport, remoteHost) {
						var pack = createUDPFrame(data, remoteHost, remoteport);
						udp.send(pack, socket.localport, socket.localhost); 
					},
					close: onclose.bind(null, socket)
				}
				return out
			}
		}

	}
}



var COMMAND = {
	Connect: 0x01,
	Bind: 0x02,
	UDP_ASSOCIATE: 0x03
};


var SOCKS5_AUTH = {
	NoAuth: 0x00,
	GSSApi: 0x01,
	UserPass: 0x02
};

var SOCKS5_RESPONSE = {
	Granted: 0x00,
	Failure: 0x01,
	NotAllowed: 0x02,
	NetworkUnreachable: 0x03,
	HostUnreachable: 0x04,
	ConnectionRefused: 0x05,
	TTLExpired: 0x06,
	CommandNotSupported: 0x07,
	AddressNotSupported: 0x08
};

function onerror(error, socket, ind) {
	log(error, ind)
	onclose(socket);
}
function onclose(socket) {
	if (socket) {
		socket.setTimeout(0);
		if (socket._buff.destroy)
			socket._buff.destroy();

		socket.removeAllListeners('close');
		socket.removeAllListeners('timeout');
		socket.removeAllListeners('data');
		socket.destroy();
		socket = null;
	}
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

function onconnect(socket, host, port, ready) {
	const buff = socket._buff

	buff.writeUInt8(0x05);
	buff.writeUInt8(2);
	buff.writeUInt8(SOCKS5_AUTH.NoAuth);
	buff.writeUInt8(SOCKS5_AUTH.UserPass);

	socket.once('data', handshake);
	socket.write(buff.toBuffer());

	function handshake(data) {
		if (data.length !== 2) {
			onerror("Negotiation Error", socket, 1);
		} else if (data[0] !== 0x05) {
			onerror("Negotiation Error (invalid version)", socket, 1);
		} else if (data[1] === 0xFF) {
			onerror("Negotiation Error (unacceptable authentication)", socket, 1);
		} else {
			if (data[1] === SOCKS5_AUTH.NoAuth) {
				sendRequest(host, port);
			} else if (data[1] === SOCKS5_AUTH.UserPass) {
				sendAuthentication("", "", host, port);
			} else {
				onerror("Negotiation Error (unknown authentication type)", socket, 1);
			}
		}
	}

	function sendAuthentication(user, pass, host, port) {
		buff.clear();
		buff.writeUInt8(0x01);
		buff.writeUInt8(Buffer.byteLength(user));
		buff.writeString(user);
		buff.writeUInt8(Buffer.byteLength(pass));
		buff.writeString(pass);

		socket.once('data', authenticationResponse);
		socket.write(buff.toBuffer());

		function authenticationResponse(data) {
			if (data.length === 2 && data[1] === 0x00) {
				sendRequest(host, port)
			} else {
				onerror("Negotiation Error (authentication failed)", socket, 1);
			}
		}
	}

	function sendRequest(host, port) {
		buff.clear();
		buff.writeUInt8(0x05);
		buff.writeUInt8(socket._cmd);
		buff.writeUInt8(0x00);
		// ipv4, ipv6, domain?
		if (net.isIPv4(host)) {
			buff.writeUInt8(0x01);
			buff.writeBuffer(utils.ip4toBuffer(host));
		} else if (net.isIPv6(host)) {
			buff.writeUInt8(0x04);
			buff.writeBuffer(utils.ip6toBuffer(host));
		} else {
			buff.writeUInt8(0x03);
			buff.writeUInt8(host.length);
			buff.writeString(host);
		}
		buff.writeUInt16BE(port);

		socket.once('data', receivedResponse);
		socket.write(buff.toBuffer());
	}

	function receivedResponse(data) {
		if (data.length < 4) {
			onerror("Negotiation Error", socket, 1);
		} else if (data[0] === 0x05 && data[1] === SOCKS5_RESPONSE.Granted) {
			if (socket._cmd === COMMAND.Connect) {
				socket.setTimeout(0);
				if (buff.destroy)
					buff.destroy();
				ready();
			} else if (socket._cmd === COMMAND.Bind || socket._cmd === COMMAND.UDP_ASSOCIATE) {

				buff.clear();
				buff.writeBuffer(data);
				buff.skip(3);

				var host;
				var port;
				var addrtype = buff.readUInt8();
				try {
					if (addrtype === 0x01) {
						host = buff.readUInt32BE();
						if (host === 0)
							host = socket.localAddress;
						else
							host = utils.int2ip(host);
					} else if (addrtype === 0x03) {
						var len = buff.readUInt8();
						host = buff.readString(len);
					} else if (addrtype === 0x04) {
						host = buff.readBuffer(16);
					} else {
						onerror("Negotiation Error (invalid host address)", socket, 1);
					}
					port = buff.readUInt16BE();

					socket.setTimeout(0);
					if (buff.destroy)
						buff.destroy();
					ready(host, port);
				} catch (ex) {
					onerror(ex, socket, 1);
				}
			}
		} else {
			onerror("Negotiation Error (" + data[1] + ")", socket, 1);
		}
	}
}

function parseUDPFrame(data) {
	const buff = new SmartBuffer(data.subarray(2))

	const frameNumber = buff.readUInt8()
	const hostType = buff.readUInt8()
	let remoteHost

	if (hostType === 0x01) {
		remoteHost = utils.int2ip(buff.readUInt32BE())
	} else if (hostType === 0x04) {
		remoteHost = buff.readBuffer(16)
	} else {
		remoteHost = buff.readString(buff.readUInt8())
	}
	const remotePort = buff.readUInt16BE()
	return {
		address: remoteHost,
		port: remotePort
	}
}

function createUDPFrame(data, host, port, frame) {
	var buff = new SmartBuffer();
	buff.writeUInt16BE(0);
	buff.writeUInt8(frame || 0x00);

	if (net.isIPv4(host)) {
		buff.writeUInt8(0x01);
		buff.writeUInt32BE(utils.ip2int(host));
	} else if (net.isIPv6(host)) {
		buff.writeUInt8(0x04);
		buff.writeBuffer(utils.ip6toBuffer(host));
	} else {
		buff.writeUInt8(0x03);
		buff.writeUInt8(Buffer.byteLength(host));
		buff.writeString(host);
	}

	buff.writeUInt16BE(port);
	buff.writeBuffer(data);
	return buff.toBuffer();
};

module.exports = init