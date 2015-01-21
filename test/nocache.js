"use strict";


var lusca = require("../index"),
  request = require("supertest"),
  mock = require("./mocks/app"),
  should = require("should");


describe("NOCACHE", function () {

  it("method", function () {
    lusca.nocache.should.be.a.Function;
  });


  it("header (nocache)", function (done) {
    var config = { nocache: true },
      app = mock(config);

    app.get("/", function *() {
      this.set("ETag", "abc");
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
      .expect("Pragma", "no-cache")
      .expect("Expires", "0")
      .expect("Etag", "abc")
      .expect(200, done);
  });


  it("header (no-etag)", function (done) {
    var config = { nocache: { noETag: true } },
      app = mock(config);

    app.get("/", function *() {
      this.set("ETag", "abc");
      this.status = 200;
    });

    request(app.listen())
      .get("/")
      .expect("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
      .expect("Pragma", "no-cache")
      .expect("Expires", "0")
      .expect(200, function (err, res) {
        if (err) {
          return done(err);
        }

        res.headers.should.not.have.property("ETag");
        done();
      });
  });

});