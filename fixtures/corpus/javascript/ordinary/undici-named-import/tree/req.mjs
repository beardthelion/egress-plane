import { request } from "undici";

export async function ping() {
  return request("https://api.example.com/ping");
}
