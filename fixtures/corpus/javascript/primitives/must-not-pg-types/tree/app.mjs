import m from "pg";

export function probe() {
  return [
    m.types,
    m.escapeIdentifier,
    m.escapeLiteral,
    m.defaults,
    m.Query,
  ];
}
