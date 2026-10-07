import m from "mongodb";

export function probe() {
  return [
    m.MongoError,
    m.MongoServerError,
    m.MongoNetworkError,
  ];
}
