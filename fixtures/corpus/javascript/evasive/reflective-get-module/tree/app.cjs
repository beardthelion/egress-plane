const path = require("path");

function probe(name) {
  return Reflect.get(path, name);
}
