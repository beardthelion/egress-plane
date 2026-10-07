import m from "axios";

export function probe() {
  return [
    m.AxiosError,
    m.CanceledError,
    m.Cancel,
    m.isAxiosError,
    m.isCancel,
  ];
}
