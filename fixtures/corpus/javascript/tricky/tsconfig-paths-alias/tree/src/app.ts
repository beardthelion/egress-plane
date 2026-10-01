import { request } from "@net/http";

export function sync() {
  return request("https://api.example.com/sync");
}
