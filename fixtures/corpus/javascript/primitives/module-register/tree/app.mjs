import m from "module";

export function probe() {
  return m.register;
}
