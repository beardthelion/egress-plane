import m from "axios";

export function probe() {
  return [
    m.CancelToken,
    m.AxiosHeaders,
    m.toFormData,
    m.formToJSON,
    m.getAdapter,
    m.mergeConfig,
    m.VERSION,
    m.HttpStatusCode,
    m.all,
    m.spread,
    m.defaults,
    m.interceptors,
  ];
}
