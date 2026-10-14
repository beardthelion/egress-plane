import m from "node-fetch";

export function probe() {
  return [
    m.Blob,
    m.File,
    m.FormData,
    m.Headers,
    m.Request,
    m.Response,
    m.blobFrom,
    m.blobFromSync,
    m.fileFrom,
    m.fileFromSync,
    m.isRedirect,
  ];
}
