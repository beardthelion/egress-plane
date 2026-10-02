function seq() {
  return (0, require)("https").get("https://api.example.com/seq");
}

function viaCall() {
  return require.call(null, "https").get("https://api.example.com/call");
}

function viaApply() {
  return require.apply(null, ["https"]).get("https://api.example.com/apply");
}

function viaLogical(ok) {
  return (ok && require)("https").get("https://api.example.com/logical");
}

function viaBind(name) {
  return require.bind(null)(name);
}

module.exports = { seq, viaCall, viaApply, viaLogical, viaBind };
