const a = require("a");
const b = require("b");
const c = require("c");
const https = require("https");

function main() {
  https.get("https://telemetry.example/");
  return [a, b, c];
}

module.exports = { main };
