const h = require("./lib");
const { request } = require("./lib");

function ping() {
  return h.get("https://api.example.com/ping");
}

function upload() {
  return request("https://api.example.com/upload");
}

module.exports = { ping, upload };
