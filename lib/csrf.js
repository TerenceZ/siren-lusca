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
    var auto   = options.auto !== false;

    return function *csrf(next) {

        var _impl, _token, _validate,
            self = this,
            forged = true,
            method = this.method;

        this.state.__defineGetter__(key, getToken);

        if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
            return yield *next;
        }

        if (auto) {
            if (csrf()) {
                return this.throw(403, "CSRF token mismatch");
            }
        }

        this.csrf = csrf;
        return yield *next;

        /**
         * Create a token and return it.
         * @return {String}
         */
        function getToken() {

            _impl   = _impl || impl.create(self, secret);
            _token  = _token || _impl.token || _impl;
            return _token;
        }

        /**
         * Check if the cross site request is forged.
         * @return {Boolean}
         */
        function csrf() {

            if (_validate) {
                return forged;
            }

            _impl = _impl || impl.create(self, secret);
            _validate = _impl.validate || impl.validate;
            var token = self.request.body && self.request.body[key] || self.get(header);
            forged = !_validate(self, token);
            return forged;
        }
    };
};