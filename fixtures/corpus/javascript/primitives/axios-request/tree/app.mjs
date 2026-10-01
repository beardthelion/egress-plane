import axios from "axios";

export function probe(target) {
  return axios.request(target);
}
