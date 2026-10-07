import m from "process";

export function probe() {
  return m.dlopen;
}
