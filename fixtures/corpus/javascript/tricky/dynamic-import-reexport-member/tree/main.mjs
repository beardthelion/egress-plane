import { get } from "./lib.mjs";

export function ping() {
  return get("https://api.example.com/ping");
}
