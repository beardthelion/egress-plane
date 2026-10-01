import childProcess from "node:child_process";

export function probe() {
  return childProcess._forkChild();
}
