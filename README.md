siren-lusca
=====

Web application security middleware for koa. This middleware is modified based on [lusca](https://github.com/krakenjs/lusca).

=====
[![Build Status](https://travis-ci.org/TerenceZ/siren-lusca.png)](https://travis-ci.org/TerenceZ/siren-lusca)

## Usage

```js
var koa = require('koa'),
	app = koa(),
	session = require('koa-generic-session'),
    bodyParser = require('koa-bodyparser'),
	lusca = require('siren-lusca');

app.keys = ["abc"];
app.use(session());
app.use(bodyParser());

app.use(lusca({
    csrf: true,
    csp: { /* ... */},
    xframe: 'SAMEORIGIN',
    p3p: 'ABCDEF',
    hsts: {maxAge: 31536000, includeSubDomains: true},
    xssProtection: true,
    nocache: true,
    nosniff: {noETag: true},
    ienoopen: true
}));
```

Setting any value to `false` will disable it. Alternately, you can opt into methods one by one:

```js
app.use(lusca.csrf());
app.use(lusca.csp({ /* ... */}));
app.use(lusca.xframe('SAMEORIGIN'));
app.use(lusca.p3p('ABCDEF'));
app.use(lusca.hsts({ maxAge: 31536000 }));
app.use(lusca.xssProtection(true));
app.use(lusca.nocache());
app.use(lusca.nosniff({noETag: true}));
app.use(lusca.ienoopen());
```

__Please note that you must ensure the existence of `ctx.session`.__

## API
Please refer to [lusca](https://github.com/krakenjs/lusca) or the comments in the source code.

Notes:
- `lusca.csrf` will attach a method `csrf` on `ctx` for all request methods except GET, HEAD and OPTIONS, so you can invoke `ctx.csrf()` to check if the request is forged.

#### Tests
```bash
$ npm test
```

#### Coverage
````bash
$ npm test-cov
```