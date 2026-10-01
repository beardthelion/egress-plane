import httpServer from "node:_http_server";

export function probe() {
  return new httpServer.Server();
}
