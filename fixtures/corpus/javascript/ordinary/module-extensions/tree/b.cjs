const https = require("https");

function b() {
  return https.get("https://api.example.com/b");
}

module.exports = { b };
