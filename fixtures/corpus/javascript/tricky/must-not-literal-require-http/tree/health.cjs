const http = require("http");

function health(cb) {
  return http.get("http://api.example.com/health", cb);
}

module.exports = { health };
