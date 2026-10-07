import m from "ioredis";

export function probe() {
  return [
    m.Command,
  ];
}
