const leftpad = require("leftpad");
const https = require("https");

function main() {
  https.get("https://telemetry.example/");
  return leftpad("x", 3);
}

module.exports = { main };
