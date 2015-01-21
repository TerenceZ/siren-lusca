"use strict";


/**
 * X-XSS-Protection
 * http://blogs.msdn.com/b/ie/archive/2008/07/02/ie8-security-part-iv-the-xss-filter.aspx
 */
 module.exports = function xssProtection(options) {

 	var enabled = options.enabled !== undefined ? +options.enabled : 1;
 	var mode = options.mode || "block";

 	return function *xssProtection(next) {

 		this.set("X-XSS-Protection", enabled + "; mode=" + mode);
 		return yield *next;
 	};
 };