"use strict";

var koa = require("koa"),
	router = require("siren-router"),
	session = require("koa-generic-session"),
	cookieSession = require("koa-session"),
	bodyParser = require("koa-bodyparser"),
	lusca = require("../..");


module.exports = function (config, type) {

	var app = koa();
	app.env = "test";

	app.keys = ["abc"];

	if (type === undefined || type === "session") {
		app.use(session());
	} else if (type === "cookie") {
		app.use(cookieSession());
	}

	app.use(bodyParser());

	if (config !== undefined) {
		app.use(lusca(config));
	}

	app.use(router(app));
	return app;
};