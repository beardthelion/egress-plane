export function run(cmd) {
  return import("child_process").then((cp) => cp.exec(cmd));
}
