"use strict";


var lusca = require("../index"),
  request = require("supertest"),
  mock = require("./mocks/app"),
  should = require("should");


describe("IE_NO_OPEN", function () {

  it("method", function () {
    lusca.nosniff.should.be.a.Function;
  });


  it("header (noopen)", function (done) {
    var config = { ienoopen: true },
      app = mock(config);

    app.get("/", function *() {
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("X-Download-Options", "noopen")
      .expect(200, done);
  });

});