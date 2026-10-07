import m from "cluster";

export function probe() {
  return [
    m.SCHED_NONE,
    m.SCHED_RR,
    m.Worker,
    m._events,
    m._eventsCount,
    m._maxListeners,
    m.disconnect,
    m.isMaster,
    m.isPrimary,
    m.isWorker,
    m.schedulingPolicy,
    m.settings,
    m.workers,
  ];
}
