import pg from "pg";

export function probe() {
  return pg.native;
}
