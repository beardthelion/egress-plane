const { request } = require("https");

function ping() {
  return request("https://api.example.com/ping");
}

module.exports = { ping };
