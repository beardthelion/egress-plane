const config = require("./config.json");

function base() {
  return config.apiBase;
}

module.exports = { base };
