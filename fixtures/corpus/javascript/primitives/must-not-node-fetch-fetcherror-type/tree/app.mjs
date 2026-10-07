import m from "node-fetch";

export function probe() {
  return [
    m.FetchError,
    m.AbortError,
  ];
}
