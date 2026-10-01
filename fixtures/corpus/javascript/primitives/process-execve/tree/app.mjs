import process from "node:process";

export function probe(target) {
  return process.execve(target);
}
