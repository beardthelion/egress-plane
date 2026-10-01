import mongodb from "mongodb";

export function probe(target) {
  return new mongodb.MongoClient(target);
}
