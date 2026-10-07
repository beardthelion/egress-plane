import m from "tls";

export function probe() {
  return [
    m.CLIENT_RENEG_LIMIT,
    m.CLIENT_RENEG_WINDOW,
    m.DEFAULT_CIPHERS,
    m.DEFAULT_ECDH_CURVE,
    m.DEFAULT_MAX_VERSION,
    m.DEFAULT_MIN_VERSION,
    m.SecureContext,
    m.checkServerIdentity,
    m.convertALPNProtocols,
    m.createSecureContext,
    m.createSecurePair,
    m.getCACertificates,
    m.getCiphers,
    m.rootCertificates,
    m.setDefaultCACertificates,
  ];
}
