const lib = require("./lib");
const { net } = require("./lib");

function health() {
  return lib.get("https://status.example.com/health");
}

function probe() {
  return net.connect(5432, "db.example.com");
}

module.exports = { health, probe };
