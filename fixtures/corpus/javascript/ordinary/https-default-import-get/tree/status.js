import https from "node:https";

export function status(cb) {
  return https.get("https://api.example.com/status", cb);
}
