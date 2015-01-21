"use strict";


var lusca = require("../index"),
  request = require("supertest"),
  mock = require("./mocks/app"),
  should = require("should");


describe("NOSNIFF", function () {

  it("method", function () {
    lusca.nosniff.should.be.a.Function;
  });


  it("header (nosniff)", function (done) {
    var config = { nosniff: true },
      app = mock(config);

    app.get("/", function *() {
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("X-Content-Type-Options", "no-sniff")
      .expect(200, done);
  });

});