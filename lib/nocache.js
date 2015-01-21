"use strict";


/**
 * No Cache - Disable the cache
 * @param {String} options options.
 */
module.exports = function p3p(options) {

	var noETag = !!(options && options.noETag);

	return function *p3p(next) {

		this.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
		this.set("Pragma", "no-cache");
		this.set("Expires", "0");

		if (noETag) {
			this.remove("ETag");
		}

		return yield *next;
	};
};