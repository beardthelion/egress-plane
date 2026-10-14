import m from "got";

export function probe() {
  return [
    m.CacheError,
    m.CancelError,
    m.HTTPError,
    m.MaxRedirectsError,
    m.ParseError,
    m.ReadError,
    m.RequestError,
    m.RetryError,
    m.TimeoutError,
    m.UploadError,
  ];
}
