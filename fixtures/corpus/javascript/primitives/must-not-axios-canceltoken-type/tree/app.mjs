import m from "axios";

export function probe() {
  return [
    m.AxiosHeaders,
    m.CancelToken,
    m.HttpStatusCode,
    m.VERSION,
    m.all,
    m.defaults,
    m.formToJSON,
    m.getAdapter,
    m.interceptors,
    m.mergeConfig,
    m.spread,
    m.toFormData,
  ];
}
