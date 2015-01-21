"use strict";


/**
 * Content Security Policy (CSP)
 * https://www.owasp.org/index.php/Content_Security_Policy
 * @param {Object} options The CSP policy.
 */
module.exports = function csp(options) {

    var policyRules  = options.policy;
    var isReportOnly = options.reportOnly;
    var reportUri    = options.reportUri;

    var name = "Content-Security-Policy";
    if (isReportOnly) {
        name += "-Report-Only";
    }

    var value = "";
    for (var key in policyRules) {
        value += key + " " + policyRules[key] + "; ";
    }

    if (reportUri) {
        value += "report-uri " + reportUri;
    }

    return function *csp(next) {

        this.set(name, value);
        return yield *next;
    };
};