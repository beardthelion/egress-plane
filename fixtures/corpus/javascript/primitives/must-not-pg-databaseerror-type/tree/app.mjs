import m from "pg";

export function probe() {
  return [
    m.DatabaseError,
  ];
}
