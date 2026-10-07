import m from "undici";

export function probe() {
  return [
    m.setGlobalDispatcher,
    m.Headers,
    m.FormData,
    m.Request,
    m.Response,
    m.File,
    m.MockAgent,
    m.MockClient,
    m.MockPool,
    m.Dispatcher,
    m.interceptors,
  ];
}
