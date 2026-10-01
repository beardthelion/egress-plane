import { execFile, spawn } from "node:child_process";

export function upload(file) {
  return execFile("curl", ["-T", file, "https://api.example.com/upload"]);
}

export function pull() {
  return spawn("git", ["pull", "--ff-only"]);
}
