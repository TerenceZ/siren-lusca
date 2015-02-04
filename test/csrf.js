"use strict";

var lusca = require("../index"),
  request = require("supertest"),
  mock = require("./mocks/app"),
  should = require("should"),
  dd = require("data-driven"),
  sessionOptions = [{
    value: "session"
  }, {
    value: "cookie"
  }],
  mapCookies = function (cookies) {
    return cookies.map(function (r) {
      return r.replace("; path=/; httponly", "");
    }).join("; ");
  };


describe("CSRF", function () {
  it("method", function () {
    lusca.csrf.should.be.a.Function;
  });

  it("expects a thrown error if no session object", function (done) {
    var app = mock({
      csrf: true
    }, "none");

    app.middleware.unshift(function *(next) {

      try {
        yield *next;
      } catch (e) {
        e.message.should.match("lusca requires `ctx.session` to be available");
        throw e;
      }
    });

    app.get("/", function *() {
      this.body = {
        token: this.state._csrf
      };
    });

    request(app.listen())
      .get("/")
      .expect(500, done);
  });

  dd(sessionOptions, function () {
    it("GETs have a CSRF token (session type: {value})", function (ctx, done) {
      var mockConfig = ctx.value === "cookie" ? {
          csrf: {
            secret: "csrfSecret"
          }
        } : {
          csrf: true
        },
        app = mock(mockConfig);

      app.get("/", function *() {
        this.body = {
          token: this.state._csrf
        };
      });

      request(app.listen())
        .get("/")
        .end(function (err, res) {
          should.exist(res.body.token);
          done(err);
        });
    });

    it("POST (200 OK with token) (session type: {value})", function (ctx, done) {
      var mockConfig = ctx.value === "cookie" ? {
          csrf: {
            secret: "csrfSecret"
          }
        } : {
          csrf: true
        },
        app = mock(mockConfig);

      app.all("/", function *() {
        this.body = {
          token: this.state._csrf
        };
      });

      request(app.listen())
        .get("/")
        .expect(200, function (err, res) {

          if (err) {
            return done(err);
          }

          request(app.listen())
            .post("/")
            .set("Cookie", mapCookies(res.headers["set-cookie"]))
            .send({
              _csrf: res.body.token
            })
            .expect(200, done);
        });
    });

    it("POST (403 Forbidden on no token) (session type: {value})", function (ctx, done) {
      var mockConfig = ctx.value === "cookie" ? {
          csrf: {
            secret: "csrfSecret"
          }
        } : {
          csrf: true
        },
        app = mock(mockConfig);

      app.post("/", function *() {
        this.status = 204;
      });

      request(app.listen())
        .post("/")
        .expect(403, done);
    });


    it("Should allow custom keys (session type: {value})", function (ctx, done) {
      var mockConfig = ctx.value === "cookie" ? {
          csrf: {
            key: "foobar",
            secret: "csrfSecret"
          }
        } : {
          csrf: {
            key: "foobar"
          }
        },
        app = mock(mockConfig);

      app.all("/", function *() {
        this.body = {
          token: this.state.foobar
        };
      });

      request(app.listen())
        .get("/")
        .expect(200, function (err, res) {
          request(app.listen())
            .post("/")
            .set("cookie", mapCookies(res.headers["set-cookie"]))
            .send({
              foobar: res.body.token
            })
            .expect(200, done);
        });
    });

    it("Token can be sent through header instead of post body (session type: {value})", function (ctx, done) {
      var mockConfig = ctx.value === "cookie" ? {
          csrf: {
            secret: "csrfSecret"
          }
        } : {
          csrf: true
        },
        app = mock(mockConfig);
      app.all("/", function *() {
        this.body = {
          token: this.state._csrf
        };
      });

      request(app.listen())
        .get("/")
        .expect(200, function (err, res) {
          request(app.listen())
            .post("/")
            .set("cookie", mapCookies(res.headers["set-cookie"]))
            .set("x-csrf-token", res.body.token)
            .send({
              name: "Test"
            })
            .expect(200, done);
        });
    });

    it("Should allow custom headers (session type: {value})", function (ctx, done) {
      var mockConfig = ctx.value === "cookie" ? {
          csrf: {
            header: "x-xsrf-token",
            secret: "csrfSecret"
          }
        } : {
          csrf: {
            header: "x-xsrf-token"
          }
        },
        app = mock(mockConfig);

      app.all("/", function *() {
        this.body = {
          token: this.state._csrf
        };
      });

      request(app.listen())
        .get("/")
        .expect(200, function (err, res) {
          request(app.listen())
            .post("/")
            .set("cookie", mapCookies(res.headers["set-cookie"]))
            .set("x-xsrf-token", res.body.token)
            .send({
              name: "Test"
            })
            .expect(200, done);
        });
    });

    it("Should allow custom secret key (session type: {value})", function (ctx, done) {
      var mockConfig = ctx.value === "cookie" ? {
          csrf: {
            secret: "csrfSecret"
          }
        } : {
          csrf: {
            secret: "_csrfSecret"
          }
        },
        app = mock(mockConfig);

      app.all("/", function *() {
        this.body = {
          token: this.state._csrf
        };
      });

      request(app.listen())
        .get("/")
        .expect(200, function (err, res) {

          if (err) {
            return done(err);
          }

          request(app.listen())
            .post("/")
            .set("cookie", mapCookies(res.headers["set-cookie"]))
            .send({
              _csrf: res.body.token
            })
            .expect(200, done);
        });
    });

    it("Should allow custom functions (session type: {value})", function (ctx, done) {
      var myToken = require("./mocks/token"),
        mockConfig = {
          csrf: {
            impl: myToken
          }
        },
        app = mock(mockConfig);

      app.all("/", function *() {
        this.body = {
          token: this.state._csrf
        };
      });

      request(app.listen())
        .get("/")
        .expect(200, function (err, res) {

          if (err) {
            return done(err);
          }

          myToken.value.should.equal(res.body.token);

          request(app.listen())
            .post("/")
            .send({
              _csrf: res.body.token
            })
            .expect(200, done);
        });
    });
  });
});