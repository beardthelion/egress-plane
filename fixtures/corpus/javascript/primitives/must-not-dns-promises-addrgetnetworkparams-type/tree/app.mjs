import m from "dns/promises";

export function probe() {
  return [
    m.ADDRGETNETWORKPARAMS,
    m.BADFAMILY,
    m.BADFLAGS,
    m.BADHINTS,
    m.BADNAME,
    m.BADQUERY,
    m.BADRESP,
    m.BADSTR,
    m.CANCELLED,
    m.CONNREFUSED,
    m.DESTRUCTION,
    m.EOF,
    m.FILE,
    m.FORMERR,
    m.LOADIPHLPAPI,
    m.NODATA,
    m.NOMEM,
    m.NONAME,
    m.NOTFOUND,
    m.NOTIMP,
    m.NOTINITIALIZED,
    m.REFUSED,
    m.SERVFAIL,
    m.TIMEOUT,
    m.getDefaultResultOrder,
    m.getServers,
    m.setDefaultResultOrder,
    m.setServers,
  ];
}
