import superagent from "superagent";

export function probe(target) {
  return superagent.delete(target);
}
