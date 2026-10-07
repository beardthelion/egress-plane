import m from "node-fetch";

export function probe() {
  return [
    m.Headers,
    m.Request,
    m.Response,
    m.FormData,
    m.Blob,
    m.File,
    m.isRedirect,
    m.fileFrom,
    m.fileFromSync,
    m.blobFrom,
    m.blobFromSync,
  ];
}
