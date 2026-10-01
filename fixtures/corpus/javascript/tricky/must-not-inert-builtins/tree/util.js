import path from "node:path";

export function describe(dir, raw) {
  const parsed = JSON.parse(raw);
  const u = new URL("https://api.example.com/v1");
  return { file: path.join(dir, "out.json"), max: Math.max(...parsed), host: u.host };
}
