"use strict";


/**
 * P3P - Platform for Privacy Preferences Project
 * http://support.microsoft.com/kb/290333
 * @param {String} value The P3P header value.
 */
module.exports = function p3p(value) {

	return function *p3p(next) {

		if (value) {
			this.set("P3P", value);
		}

		return yield *next;
	};
};