import m from "module";

export function probe() {
  return [
    m.SourceMap,
    m._debug,
    m._findPath,
    m._nodeModulePaths,
    m._readPackage,
    m._resolveLookupPaths,
    m._stat,
    m.builtinModules,
    m.constants,
    m.enableCompileCache,
    m.findPackageJSON,
    m.findSourceMap,
    m.flushCompileCache,
    m.getCompileCacheDir,
    m.getSourceMapsSupport,
    m.isBuiltin,
    m.length,
    m.name,
    m.setSourceMapsSupport,
    m.stripTypeScriptTypes,
    m.wrap,
    m.wrapper,
  ];
}
