"use strict";


/**
 * Xframes
 * https://www.owasp.org/index.php/Clickjacking
 * @param {String} value The XFRAME header value, e.g. DENY, SAMEORIGIN.
 */
module.exports = function xframes(value) {

	return function *xframes(next) {

		this.set("X-FRAME-OPTIONS", value);
		return yield *next;
	};
};