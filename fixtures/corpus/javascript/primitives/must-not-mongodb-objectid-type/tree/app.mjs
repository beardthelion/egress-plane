import m from "mongodb";

export function probe() {
  return [
    m.ObjectId,
    m.Long,
    m.Decimal128,
    m.Binary,
    m.BSON,
    m.Timestamp,
    m.ReadPreference,
    m.WriteConcern,
    m.ReturnDocument,
  ];
}
