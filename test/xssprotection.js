"use strict";


var lusca = require("../index"),
  request = require("supertest"),
  mock = require("./mocks/app"),
  should = require("should");



describe("xssProtection", function () {

  it("method", function () {
    lusca.xssProtection.should.be.a.Function;
  });

  it("header (enabled)", function (done) {
    var config = { xssProtection: true },
      app = mock(config);

    app.get("/", function *() {
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("X-XSS-Protection", "1; mode=block")
      .expect(200, done);
  });

  it("header (enabled; custom mode)", function (done) {
    var config = { xssProtection: { enabled: 1, mode: "foo" } },
      app = mock(config);

    app.get("/", function *() {
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("X-XSS-Protection", "1; mode=foo")
      .expect(200, done);
  });

  it("header (enabled is boolean; custom mode)", function (done) {
    var config = { xssProtection: { enabled: true } },
      app = mock(config);

    app.get("/", function *() {
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("X-XSS-Protection", "1; mode=block")
      .expect(200, done);
  });

  it("header (!enabled)", function (done) {
    var config = { xssProtection: { enabled: 0 } },
      app = mock(config);

    app.get("/", function *() {
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("X-XSS-Protection", "0; mode=block")
      .expect(200, done);
  });
});