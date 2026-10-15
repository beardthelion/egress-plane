const axios = require("axios");
const makeClient = (o) => ({ base: o.baseURL });

function probe(u) {
  return makeClient({ baseURL: u });
}
