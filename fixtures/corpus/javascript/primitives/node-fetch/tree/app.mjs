import nodeFetch from "node-fetch";

export function probe(target) {
  return nodeFetch(target);
}
