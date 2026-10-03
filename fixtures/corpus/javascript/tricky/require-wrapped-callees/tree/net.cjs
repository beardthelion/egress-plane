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

function computedCall() {
  return require["call"](null, "https").get("https://api.example.com/computed-call");
}

function computedApply() {
  return require["apply"](null, ["https"]).get("https://api.example.com/computed-apply");
}

function computedTemplate() {
  return require[`call`](null, "https").get("https://api.example.com/computed-template");
}

function computedBind() {
  return require["bind"](null)("https");
}

function computedKey(k) {
  return require[k](null, "https");
}

module.exports = {
  seq,
  viaCall,
  viaApply,
  viaLogical,
  viaBind,
  computedCall,
  computedApply,
  computedTemplate,
  computedBind,
  computedKey,
};
