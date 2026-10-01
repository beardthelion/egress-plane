import { widget } from "@acme/widgets";
import fp from "lodash/fp";

export function render(xs) {
  return widget(fp.map((x) => x * 2)(xs));
}
