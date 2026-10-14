import m from "mongodb";

export function probe() {
  return [
    m.BSON,
    m.Binary,
    m.Decimal128,
    m.Long,
    m.ObjectId,
    m.ReadPreference,
    m.ReturnDocument,
    m.Timestamp,
    m.WriteConcern,
  ];
}
