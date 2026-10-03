import { createRequire } from "node:module";

const r = createRequire(import.meta.url);

export function createdCall() {
  return r["call"](null, "https").get("https://api.example.com/created-call");
}

export function createdBind() {
  return r["bind"](null)("https");
}
