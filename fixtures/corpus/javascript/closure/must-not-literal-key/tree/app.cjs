const lib = require("probeclientpkg");

function probe(k, u) {
  const o = lib.get();
  return o.open(u);
}
