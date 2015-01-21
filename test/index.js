"use strict";

var lusca = require("..");
var request = require("supertest");
var should = require("should");
var mock = require("./mocks/app");
var lusca = require("../index");

describe("lusca", function () {

  it("method", function () {
    
    lusca.should.be.Function;
  });


  it("headers", function (done) {
    var config = require("./mocks/config/all"),
      app = mock(config);

    app.use(function *() {
      
      this.status = 204;
    });

    request(app.listen())
      .get("/")
      .expect("X-FRAME-OPTIONS", config.xframe)
      .expect("P3P", config.p3p)
      .expect("Strict-Transport-Security", "max-age=" + config.hsts.maxAge)
      .expect("Content-Security-Policy-Report-Only", "default-src *; report-uri " + config.csp.reportUri)
      .expect("X-XSS-Protection", "1; mode=block")
      .expect(204, done);
  });
});