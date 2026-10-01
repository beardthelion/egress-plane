import childProcess from "node:child_process";

export function probe() {
  return new childProcess.ChildProcess();
}
