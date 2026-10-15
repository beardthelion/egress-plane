const http = require("http");
const path = require("path");

function probe(u) {
  return http.get.call(null, u);
}
