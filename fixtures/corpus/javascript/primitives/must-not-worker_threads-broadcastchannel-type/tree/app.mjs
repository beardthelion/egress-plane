import m from "worker_threads";

export function probe() {
  return [
    m.BroadcastChannel,
    m.MessageChannel,
    m.MessagePort,
    m.SHARE_ENV,
    m.getEnvironmentData,
    m.isInternalThread,
    m.isMainThread,
    m.isMarkedAsUntransferable,
    m.markAsUncloneable,
    m.markAsUntransferable,
    m.moveMessagePortToContext,
    m.parentPort,
    m.postMessageToThread,
    m.receiveMessageOnPort,
    m.resourceLimits,
    m.setEnvironmentData,
    m.threadId,
    m.threadName,
    m.workerData,
  ];
}
