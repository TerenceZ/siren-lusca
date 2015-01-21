"use strict";


/**
 * Restrict Untrusted HTML
 * http://blogs.msdn.com/b/ie/archive/2008/07/02/ie8-security-part-v-comprehensive-protection.aspx
 */
module.exports = function ienoopen() {

	return function *ienoopen(next) {

		this.set("X-Download-Options", "noopen");
		return yield *next;
	};
};