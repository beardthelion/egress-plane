import https from "node:https";

export function probe() {
  return https.createServer();
}
