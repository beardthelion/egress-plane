import m from "sqlite";

export function probe() {
  return [
    m.StatementSync,
    m.backup,
    m.constants,
  ];
}
