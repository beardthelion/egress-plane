import { client } from "./api.js";

export function me() {
  return client.get("https://api.example.com/me");
}
