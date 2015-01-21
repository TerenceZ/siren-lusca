"use strict";

var crypto = require("crypto");

var LENGTH = 10;


function create(context, secretKey) {

    var session = context.session;
    if (session === undefined) {
        throw new Error("lusca requires `ctx.session` to be available in order to maintain state");
    }

    var secret = session[secretKey];
    if (!secret) {
        secret = session[secretKey] = crypto.pseudoRandomBytes(LENGTH).toString("base64");
    }

    return {
        token: tokenize(salt(LENGTH), secret),
        validate: function validate(context, token) {

            if (typeof token !== "string") {
                return false;
            }

            return token === tokenize(token.slice(0, LENGTH), context.session[secretKey]);
        }
    };
}


function tokenize(salt, secret) {
    return salt + crypto.createHash("sha1").update(salt + secret).digest("base64");
}


function salt(len) {
    var str = "";
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for (var i = -1; ++i < len;) {
        str += chars[Math.floor(Math.random() * chars.length)];
    }

    return str;
}


module.exports = {
    create: create
};