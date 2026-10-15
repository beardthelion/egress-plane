const http = require("http");
const path = require("path");

function probe(u) {
  return path.join.call(null, u);
}
