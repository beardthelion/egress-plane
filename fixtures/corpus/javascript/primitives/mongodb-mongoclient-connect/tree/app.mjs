import mongodb from "mongodb";

export function probe(target) {
  return mongodb.MongoClient.connect(target);
}
