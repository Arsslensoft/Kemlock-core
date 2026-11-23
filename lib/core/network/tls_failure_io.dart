import 'dart:io' show HandshakeException;

/// Whether [error] is a TLS handshake failure, as a certificate the phone refused.
bool isTlsFailure(Object error) => error is HandshakeException;
