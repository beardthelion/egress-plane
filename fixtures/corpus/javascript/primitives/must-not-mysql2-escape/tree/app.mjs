import m from "mysql2";

export function probe() {
  return [
    m.escape,
    m.escapeId,
    m.format,
    m.raw,
    m.Types,
    m.Charsets,
  ];
}
