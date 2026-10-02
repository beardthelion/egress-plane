if (typeof require !== "undefined" && require.main === module) {
  const here = require.resolve("./cli.cjs");
  const cached = Object.keys(require.cache);
  console.log(here, cached);
}
