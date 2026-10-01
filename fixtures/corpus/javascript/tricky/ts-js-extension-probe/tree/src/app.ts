import { request } from "./client.js";

export function send() {
  return request("https://api.example.com/send");
}
