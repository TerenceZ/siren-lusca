"use strict";

var lusca = require("../index"),
  request = require("supertest"),
  mock = require("./mocks/app"),
  should = require("should");


describe("HSTS", function () {

  it("method", function () {
    lusca.hsts.should.be.a.Function;
  });


  it("header (maxAge)", function (done) {
    var config = { hsts: { maxAge: 31536000 } },
      app = mock(config);

    app.get("/", function *() {
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("Strict-Transport-Security", "max-age=" + config.hsts.maxAge)
      .expect(200, done);
  });


  it("header (maxAge 0)", function (done) {
    var config = { hsts: { maxAge: 0 } },
      app = mock(config);

    app.get("/", function *() {
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("Strict-Transport-Security", "max-age=" + config.hsts.maxAge)
      .expect(200, done);
  });


  it("header (maxAge; includeSubDomains)", function (done) {
    var config = { hsts: { maxAge: 31536000, includeSubDomains: true } },
      app = mock(config);

    app.get("/", function *() {
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("Strict-Transport-Security", "max-age=" + config.hsts.maxAge + "; includeSubDomains")
      .expect(200, done);
  });


  it("header (missing maxAge)", function (done) {
    var config = { hsts: {} },
      app = mock(config);

    app.get("/", function *() {
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect(200)
      .end(function (err, res) {
        should.not.exist(res.headers["Strict-Transport-Security"]);
        done(err);
      });
  });

});