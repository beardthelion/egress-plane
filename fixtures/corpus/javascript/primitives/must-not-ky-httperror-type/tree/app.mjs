import m from "ky";

export function probe() {
  return [
    m.HTTPError,
    m.TimeoutError,
  ];
}
