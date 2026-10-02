import https from "node:https";

export function call(h) {
  return https.request({ hostname: h, headers: { Authorization: "Bearer JSPW2FAKE" } });
}
