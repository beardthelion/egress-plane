import superagent from "superagent";

export function probe() {
  return superagent.agent();
}
