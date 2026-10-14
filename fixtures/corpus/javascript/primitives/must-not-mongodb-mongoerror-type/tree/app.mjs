import m from "mongodb";

export function probe() {
  return [
    m.MongoError,
    m.MongoNetworkError,
    m.MongoServerError,
  ];
}
