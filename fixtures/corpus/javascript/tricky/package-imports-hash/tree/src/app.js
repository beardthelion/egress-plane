import { request } from "#net";

export function send() {
  return request("https://api.example.com/send");
}
