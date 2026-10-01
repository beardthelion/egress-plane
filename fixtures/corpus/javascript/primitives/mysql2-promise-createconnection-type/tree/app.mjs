import mysql2Promise from "mysql2/promise";

export function probe(target) {
  return mysql2Promise.createConnection(target);
}
