"use strict";
const storage = require("../../core/storage")
const that = {
    get,
    getUser: undefined,
    save: function () {
        save()
        storage.write()
    },
}

storage.on("write", save)
function save() {
    if(!storage.data) storage.data ={} 
    if (!("vmess" in storage.data)) {
        storage.data.vmess = {}
    }
    const users = that.getUser()
    for (const i in users) {
        storage.data.vmess[i] = users[i]
    }
}


function get(tag) {
    if (!("vmess" in storage.data)) {
        storage.data.vmess = {}
    }
    const users = storage.data.vmess[tag]
    if (!users)
        return {}
    return users;
}


module.exports = that