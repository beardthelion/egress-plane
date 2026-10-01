import axios from "axios";

export function probe(target) {
  return axios.patch(target);
}
