import m from "mysql2/promise";

export function probe() {
  return [
    m.Charsets,
    m.Types,
    m.escape,
    m.escapeId,
    m.format,
    m.raw,
  ];
}
