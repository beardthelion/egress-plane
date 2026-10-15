const http = require("http");

function probe() {
  return http.get;
}
