import m from "ky";

export function probe() {
  return [
    m.stop,
  ];
}
