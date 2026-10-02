import { omit } from "lodash";

export function shape(payload) {
  return omit(payload, ["secret"]);
}
