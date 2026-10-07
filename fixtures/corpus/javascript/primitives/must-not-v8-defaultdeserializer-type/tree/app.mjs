import m from "v8";

export function probe() {
  return [
    m.DefaultDeserializer,
    m.DefaultSerializer,
    m.Deserializer,
    m.GCProfiler,
    m.Serializer,
    m.cachedDataVersionTag,
    m.deserialize,
    m.getCppHeapStatistics,
    m.getHeapCodeStatistics,
    m.getHeapSnapshot,
    m.getHeapSpaceStatistics,
    m.getHeapStatistics,
    m.isStringOneByteRepresentation,
    m.promiseHooks,
    m.serialize,
    m.setHeapSnapshotNearHeapLimit,
    m.startupSnapshot,
    m.stopCoverage,
    m.takeCoverage,
    m.writeHeapSnapshot,
  ];
}
