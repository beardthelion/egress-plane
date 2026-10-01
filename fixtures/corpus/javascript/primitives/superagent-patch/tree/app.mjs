import superagent from "superagent";

export function probe(target) {
  return superagent.patch(target);
}
