import m from "node-fetch";

export function probe() {
  return [
    m.AbortError,
    m.FetchError,
  ];
}
