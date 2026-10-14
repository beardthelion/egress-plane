import m from "axios";

export function probe() {
  return [
    m.AxiosError,
    m.Cancel,
    m.CanceledError,
    m.isAxiosError,
    m.isCancel,
  ];
}
