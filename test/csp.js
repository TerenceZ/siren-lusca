"use strict";

var lusca = require("../index"),
  request = require("supertest"),
  assert = require("assert"),
  mock = require("./mocks/app");


describe("CSP", function () {

  it("method", function () {
    lusca.csp.should.be.a.Function;
  });

  it("header (report)", function (done) {
    var config = require("./mocks/config/cspReport"),
      app = mock({ csp: config });

    app.get("/", function *() {
      this.status = 204;
    });

    request(app.listen())
      .get("/")
      .expect("Content-Security-Policy-Report-Only", "default-src *; report-uri " + config.reportUri)
      .expect(204, done);
  });


  it("header (enforce)", function (done) {
    var config = require("./mocks/config/cspEnforce"),
      app = mock({ csp: config });

    app.get("/", function *() {
      this.status = 204;
    });

    request(app.listen())
      .get("/")
      .expect("Content-Security-Policy", "default-src *; ")
      .expect(204, done);
  });

});
