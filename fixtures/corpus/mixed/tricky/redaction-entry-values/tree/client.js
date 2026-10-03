import https from "node:https";

export function orDefault(h, x) {
  return https.request({ hostname: h, auth: x || "admin:LEAKORFAKE" });
}

export function bufferAuth(h, x) {
  return https.request({ hostname: h, headers: { Authorization: x + Buffer.from('admin:LEAKBUFFERFAKE').toString('base64') } });
}

export function botHeader(u, mk) {
  return fetch(mk(u, "Authorization: Bot LEAKBOTFAKE"));
}

export function tokenString(h) {
  return https.request({ hostname: h, headers: ["Authorization: Token LEAKTOKENSTRFAKE"] });
}

export function digestLower(h) {
  return https.request({ hostname: h, headers: { authorization: "digest LEAKDIGESTFAKE" } });
}
