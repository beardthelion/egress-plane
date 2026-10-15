function probe(k, m) {
  require.cache[k] = m;
}
