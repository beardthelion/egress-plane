import mysql2 from "mysql2";

export function probe(target) {
  return mysql2.connect(target);
}
