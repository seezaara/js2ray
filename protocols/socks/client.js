const net = require('net');
const dgram = require('dgram');
const utils = require('../../core/utils');

function init(data, remoteNetwork) {
	return function (address, port, cmd, localConnect, localMessage, localClose) {
		const network = data.networks.length === 1
			? data.networks[0]
			: data.networks[Math.floor(Math.random() * data.networks.length)];

		const selectedUser = data.users?.length
			? data.users[Math.floor(Math.random() * data.users.length)]
			: null;

		if (typeof localMessage === "object") {
			const socket = remoteNetwork(network.address, network.port, cmd, () => {
				onconnect(socket, address, port, () => {
					localConnect();
					localMessage.pipe(socket);
					socket.pipe(localMessage);
				}, selectedUser);
			}, null, null);

			socket._cmd = cmd;
			return;
		}

		if (cmd === 1) {
			const socket = remoteNetwork(network.address, network.port, cmd, onconnected, null, localClose);
			socket._cmd = cmd;

			function onconnected() {
				onconnect(socket, address, port, () => {
					localConnect();
					socket.on('data', localMessage);
				}, selectedUser);
			}

			return {
				message: socket.write.bind(socket),
				close: () => onclose(socket)
			};
		} else {
			const socket = remoteNetwork(network.address, network.port, cmd, onconnected, null, localClose);
			socket._cmd = cmd;
			const udp = dgram.createSocket('udp4');

			function onconnected() {
				onconnect(socket, "0.0.0.0", 0, (localhost, localport) => {
					socket.localhost = localhost;
					socket.localport = localport;
					udp.on('message', (msg) => {
						const headLength = validateSocks5UDPHead(msg);
						if (!headLength) return;
						localMessage(msg.slice(headLength), parseUDPFrame(msg));
					});
					udp.on('error', localClose);
					udp.bind(localConnect);
				}, selectedUser);
			}

			return {
				message: (data, remoteport, remoteHost) => {
					const pack = createUDPFrame(data, remoteHost, remoteport);
					udp.send(pack, socket.localport, socket.localhost);
				},
				close: () => onclose(socket)
			};
		}
	};
}

function onconnect(socket, host, port, ready, selectedUser) {
	const handshake = Buffer.from([0x05, 0x02, 0x00, 0x02]);
	socket.once('data', handleHandshake);
	socket.write(handshake);

	function handleHandshake(data) {
		if (data.length !== 2 || data[0] !== 0x05) return onerror("Negotiation Error", socket);
		if (data[1] === 0xFF) return onerror("No acceptable auth", socket);
		if (data[1] === 0x00) {
			sendRequest();
		} else if (data[1] === 0x02) {
			sendAuth();
		} else {
			onerror("Unknown auth method", socket);
		}
	}

	function sendAuth() {
		const user = selectedUser?.user || "";
		const pass = selectedUser?.pass || "";
		const userBuf = Buffer.from(user);
		const passBuf = Buffer.from(pass);
		const authBuf = Buffer.concat([
			Buffer.from([0x01, userBuf.length]),
			userBuf,
			Buffer.from([passBuf.length]),
			passBuf
		]);
		socket.once('data', handleAuth);
		socket.write(authBuf);
	}

	function handleAuth(data) {
		if (data.length === 2 && data[1] === 0x00) {
			sendRequest();
		} else {
			onerror("Authentication failed", socket);
		}
	}

	function sendRequest() {
		let addrBuf;
		if (net.isIPv4(host)) {
			addrBuf = Buffer.concat([
				Buffer.from([0x01]),
				utils.ip4toBuffer(host)
			]);
		} else if (net.isIPv6(host)) {
			addrBuf = Buffer.concat([
				Buffer.from([0x04]),
				utils.ip6toBuffer(host)
			]);
		} else {
			const hostBuf = Buffer.from(host);
			addrBuf = Buffer.concat([
				Buffer.from([0x03, hostBuf.length]),
				hostBuf
			]);
		}

		const reqBuf = Buffer.concat([
			Buffer.from([0x05, socket._cmd, 0x00]),
			addrBuf,
			Buffer.from([(port >> 8) & 0xff, port & 0xff])
		]);

		socket.once('data', handleResponse);
		socket.write(reqBuf);
	}

	function handleResponse(data) {
		if (data.length < 4 || data[0] !== 0x05 || data[1] !== 0x00) {
			return onerror("Request denied: " + data[1], socket);
		}

		if (socket._cmd === 0x01) {
			ready();
		} else {
			let addrType = data[3];
			let offset = 4;
			let host;
			if (addrType === 0x01) {
				host = utils.int2ip(data.readUInt32BE(offset));
				offset += 4;
			} else if (addrType === 0x03) {
				const len = data[offset];
				offset += 1;
				host = data.toString("utf8", offset, offset + len);
				offset += len;
			} else if (addrType === 0x04) {
				host = data.slice(offset, offset + 16);
				offset += 16;
			} else {
				return onerror("Invalid address type", socket);
			}
			const port = data.readUInt16BE(offset);
			ready(host, port);
		}
	}
}

function parseUDPFrame(data) {
	let offset = 2;
	const frame = data[offset++];
	const hostType = data[offset++];
	let host;

	if (hostType === 0x01) {
		host = utils.int2ip(data.readUInt32BE(offset));
		offset += 4;
	} else if (hostType === 0x03) {
		const len = data[offset++];
		host = data.toString("utf8", offset, offset + len);
		offset += len;
	} else if (hostType === 0x04) {
		host = data.slice(offset, offset + 16);
		offset += 16;
	}

	const port = data.readUInt16BE(offset);
	return { address: host, port };
}

function createUDPFrame(data, host, port, frame = 0x00) {
	const addr = (() => {
		if (net.isIPv4(host)) {
			return Buffer.concat([Buffer.from([0x01]), utils.ip4toBuffer(host)]);
		} else if (net.isIPv6(host)) {
			return Buffer.concat([Buffer.from([0x04]), utils.ip6toBuffer(host)]);
		} else {
			const b = Buffer.from(host);
			return Buffer.concat([Buffer.from([0x03, b.length]), b]);
		}
	})();
	const portBuf = Buffer.from([(port >> 8) & 0xff, port & 0xff]);
	return Buffer.concat([Buffer.from([0x00, 0x00, frame]), addr, portBuf, data]);
}

function validateSocks5UDPHead(buf) {
	if (buf[0] !== 0 || buf[1] !== 0) return false;
	let minLength = 6;
	if (buf[3] === 0x01) minLength += 4;
	else if (buf[3] === 0x03) minLength += buf[4];
	else if (buf[3] === 0x04) minLength += 16;
	else return false;
	if (buf.length < minLength) return false;
	return minLength;
}

function onerror(error, socket, ind) {
	log(error, ind)
	onclose(socket);
}

function onclose(socket) {
	if (socket) {
		socket.setTimeout(0);
		socket.removeAllListeners();
		socket.destroy();
	}
}

module.exports = init;
