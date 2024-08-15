"use strict";

const validator = require("./validator")
module.exports = {
    server: require('./server'),
    client: require('./client'),
    api: {
        getUserByEmail: validator.getUserByEmail,
        getUsers: validator.getUser,
        addUsers: validator.addUsers,
        removeUsers: validator.removeUsers
    }
}