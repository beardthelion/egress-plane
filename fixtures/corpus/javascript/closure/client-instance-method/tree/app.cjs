const axios = require("axios");

function probe(u) {
  return axios.create({ baseURL: u });
}
