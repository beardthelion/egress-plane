import { request } from "./lib/index.js";

export function upload() {
  return request("https://api.example.com/upload");
}
