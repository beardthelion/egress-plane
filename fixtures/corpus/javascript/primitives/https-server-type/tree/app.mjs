import https from "node:https";

export function probe() {
  return new https.Server();
}
