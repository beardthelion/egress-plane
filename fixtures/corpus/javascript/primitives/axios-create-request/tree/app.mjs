import axios from "axios";

export function probe(target) {
  const s = axios.create();
  return s.request(target);
}
