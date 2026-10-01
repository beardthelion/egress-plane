import { get as httpGet } from "node:http";

export function health(cb) {
  return httpGet("http://api.example.com/health", cb);
}
