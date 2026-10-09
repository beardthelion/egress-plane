const axios = require("axios");

function wasCanceled(err) {
  return axios.isCancel(err);
}

module.exports = { wasCanceled };
