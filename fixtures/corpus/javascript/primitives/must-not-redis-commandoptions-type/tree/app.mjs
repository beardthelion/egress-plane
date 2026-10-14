import m from "redis";

export function probe() {
  return [
    m.RedisFlushModes,
    m.SchemaFieldTypes,
    m.commandOptions,
    m.defineScript,
  ];
}
