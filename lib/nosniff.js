"use strict";


/**
 * Don't Infer the MIME Type
 */
module.exports = function nosniff() {

	return function *nosniff(next) {

		this.set("X-Content-Type-Options", "no-sniff");
		return yield *next;
	};
};