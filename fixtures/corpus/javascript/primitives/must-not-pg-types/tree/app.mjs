import m from "pg";

export function probe() {
  return [
    m.Query,
    m.defaults,
    m.escapeIdentifier,
    m.escapeLiteral,
    m.types,
  ];
}
