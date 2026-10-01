import pg from "pg";

export function probe(target) {
  return new pg.Pool(target);
}
