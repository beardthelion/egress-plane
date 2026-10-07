import m from "test";

export function probe() {
  return [
    m.after,
    m.afterEach,
    m.assert,
    m.before,
    m.beforeEach,
    m.describe,
    m.it,
    m.length,
    m.name,
    m.only,
    m.skip,
    m.snapshot,
    m.suite,
    m.test,
    m.todo,
  ];
}
