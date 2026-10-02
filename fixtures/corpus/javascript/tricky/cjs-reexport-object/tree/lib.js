const https = require("https");

module.exports = { get: https.get, net: require("net") };
