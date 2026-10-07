import m from "redis";

export function probe() {
  return [
    m.commandOptions,
    m.defineScript,
    m.RedisFlushModes,
    m.SchemaFieldTypes,
  ];
}
