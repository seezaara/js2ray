

function init(networks, remoteNetwork) {
    const data = networks[Math.floor(Math.random() * networks.length)]
    return function (localsocket) {
        localsocket.pause();
        var remote = remoteNetwork(
            data.address,
            data.port,
            data.option,
            function () {
                localsocket.resume()
            },
            localsocket.localMessage,
            localsocket.localClose
        )
        return {
            message: remote.message,
            close: remote.close,
        }
    }
}
module.exports = init