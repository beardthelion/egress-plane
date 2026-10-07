import m from "sqlite";

export function probe() {
  return m.DatabaseSync;
}
