import { get } from "@acme/client";

export function health(cb) {
  return get("http://api.example.com/health", cb);
}
