import m from "undici";

export function probe() {
  return [
    m.Dispatcher,
    m.File,
    m.FormData,
    m.Headers,
    m.MockAgent,
    m.MockClient,
    m.MockPool,
    m.Request,
    m.Response,
    m.interceptors,
    m.setGlobalDispatcher,
  ];
}
