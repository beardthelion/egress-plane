import mysql2 from "mysql2";

export function probe() {
  return mysql2.createPoolCluster();
}
