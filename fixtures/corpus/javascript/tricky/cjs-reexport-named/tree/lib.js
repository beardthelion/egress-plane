const https = require("https");

exports.tls = require("tls");
module.exports.get = https.get;
module.exports.net = require("net");
