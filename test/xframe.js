"use strict";


var lusca = require("../index"),
  request = require("supertest"),
  mock = require("./mocks/app"),
  should = require("should");


describe("XFRAME", function () {

  it("method", function () {
    lusca.xframe.should.be.a.Function;
  });


  it("header (deny)", function (done) {
    var config = { xframe: "DENY" },
      app = mock(config);

    app.get("/", function *() {
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("X-FRAME-OPTIONS", config.xframe)
      .expect(200, done);
  });


  it("header (sameorigin)", function (done) {
    var config = { xframe: "SAMEORIGIN" },
      app = mock(config);

    app.get("/", function *() {
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("X-FRAME-OPTIONS", config.xframe)
      .expect(200, done);
  });

});