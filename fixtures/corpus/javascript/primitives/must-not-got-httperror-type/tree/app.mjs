import m from "got";

export function probe() {
  return [
    m.HTTPError,
    m.RequestError,
    m.TimeoutError,
    m.CancelError,
    m.ParseError,
    m.MaxRedirectsError,
    m.ReadError,
    m.UploadError,
    m.CacheError,
    m.RetryError,
  ];
}
