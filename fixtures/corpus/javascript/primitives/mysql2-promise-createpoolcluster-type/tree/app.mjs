import mysql2Promise from "mysql2/promise";

export function probe() {
  return mysql2Promise.createPoolCluster();
}
