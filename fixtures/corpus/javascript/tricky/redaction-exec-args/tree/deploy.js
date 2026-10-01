import { execFile } from "node:child_process";

export function deploy() {
  return execFile("curl", ["-H", "Authorization: token ghp_FAKE0123456789", "https://api.example.com/deploy"]);
}
