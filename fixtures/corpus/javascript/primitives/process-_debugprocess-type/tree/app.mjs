import m from "process";

export function probe() {
  return m._debugProcess;
}
