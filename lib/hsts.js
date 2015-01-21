"use strict";


/**
 * HSTS - Http Strict Transport Security
 * https://www.owasp.org/index.php/HTTP_Strict_Transport_Security
 * @param {Object} options
 *     maxAge {Number} The max age of the header. Required.
 *     includeSubDomains {Boolean} 
 */
 module.exports = function hsts(options) {

    var value = options.maxAge !== undefined ? "max-age=" + options.maxAge : "";
    value += (value && options.includeSubDomains) ? "; includeSubDomains" : "";

    return function *hsts(next) {

        if (value) {
            this.set("Strict-Transport-Security", value);
        }

        return yield *next;
    };
 };