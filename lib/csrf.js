"use strict";

var token = require("./token");


/**
 * CSRF
 * https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
 * @param {Object} options
 *    key {String} The name of the CSRF token in the model. Default "_csrf".
 *    impl {Object} An object with create/validate methods for custom tokens. Optional.
 *    header {String} The name of the response header containing the CSRF token. Default "x-csrf-token".
 */
module.exports = function csrf(options) {

    var key    = options.key || "_csrf";
    var impl   = options.impl || token;
    var header = options.header || "x-csrf-token";
    var secret = options.secret || "_csrfSecret";

    return function *csrf(next) {

        var _impl    = impl.create(this, secret);
        var validate = impl.validate || _impl.validate;
        var _token   = _impl.token || _impl;

        this.state[key] = _token;

        var method = this.method;
        if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
            return yield *next;
        }

        _token = this.request.body && this.request.body[key] || this.get(header);
        if (validate(this, _token)) {
            return yield *next;
        }

        return this.throw(403, "CSRF token mismatch");
    };
};