"use strict";


var lusca = require("../index"),
  request = require("supertest"),
  mock = require("./mocks/app"),
  should = require("should");


describe("P3P", function () {

    it("method", function () {
        lusca.p3p.should.be.a.Function;
    });


    it("header", function (done) {
        var config = { p3p: "MY_P3P_VALUE" },
            app = mock(config);

        app.get("/", function *() {
            this.status = 200;
        });

        request(app.listen())
            .get("/")
            .expect("P3P", config.p3p)
            .expect(200, done);
    });

});