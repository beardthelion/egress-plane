const fp = require("lodash/fp");
const chart = require("chart.js");
const pkg = require("@my.org/pkg");

module.exports = { m: fp.map, c: chart.plot, p: pkg.run };
