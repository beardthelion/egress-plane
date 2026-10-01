import childProcess from "node:child_process";

export function probe(target) {
  return childProcess.execSync(target);
}
