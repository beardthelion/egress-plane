import httpClient from "node:_http_client";

export function probe() {
  return new httpClient.ClientRequest();
}
