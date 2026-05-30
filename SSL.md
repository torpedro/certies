# SSL certificate concepts

This document explains what each file in the store does, how the pieces fit together, and how a server uses them to authenticate clients.

## The chain of trust

Every certificate in this system is either a CA certificate or signed by the CA. The CA's signature is what makes a client certificate trustworthy — a server that holds the CA certificate can verify that any client certificate was issued by the same authority, and therefore belongs to someone who was explicitly provisioned.

```
CA certificate (self-signed)
  └── client certificate (alice/laptop)
  └── client certificate (alice/phone)
  └── client certificate (bob/desktop)
```

## Files

### `ca/ca.key` — CA private key

The CA's private key. It is used to sign every client certificate that is issued. This is the most sensitive file in the store — anyone who obtains it can issue certificates that your server will trust. It is stored with mode `0600` and should never leave the machine running `certies`.

### `ca/ca.crt` — CA certificate

The CA's self-signed certificate. It contains the CA's public key and identity. This file is not secret and needs to be deployed to every server that will authenticate clients — it is what the server uses to verify that a presented client certificate was signed by your CA.

The CA certificate has a long validity period (10 years by default) and must be replaced along with all client certificates if it expires or is compromised.

### `clients/<client>/<device>/<device>.key` — client private key

The client's private key. It never leaves the client device — it is used by the client during the TLS handshake to prove that it holds the private key corresponding to the public key in its certificate. It is stored with mode `0600`.

If a key password was set at issuance, the file is encrypted with AES-256-CBC and the client software will need the password to use it.

### `clients/<client>/<device>/<device>.crt` — client certificate

The client's certificate, signed by the CA. It contains:

- The client's public key
- The client's identity (`CN=alice/laptop`)
- The validity window (`notBefore` / `notAfter`)
- A serial number unique within this CA
- The CA's signature over all of the above

During a TLS handshake the client presents this certificate to the server. The server checks the CA signature, checks that the serial is not in the CRL, and checks that the certificate has not expired.

### `clients/<client>/<device>/<device>.p12` — PKCS#12 bundle

A single encrypted file that bundles the client private key, the client certificate, and the CA certificate chain together. This is the file you distribute to a client device — most operating systems, browsers, and VPN clients can import a `.p12` directly into their certificate store.

The P12 is always encrypted with a password. The private key inside may additionally be encrypted with its own password if one was set at issuance.

### `crl/crl.pem` — Certificate Revocation List

A signed list of certificate serial numbers that have been revoked before their expiry date. The CRL is signed by the CA and has its own validity window (`thisUpdate` / `nextUpdate`).

Servers that check the CRL will refuse connections from any client whose serial appears in it, even if the certificate itself is not yet expired. The CRL must be re-fetched or regenerated before it expires — use `certies renew-crl` to extend its validity. It is regenerated automatically whenever a certificate is revoked.

## How client authentication works

1. The server is configured with `ca.crt` as its trusted CA and `crl.pem` as its revocation list.
2. The client is provisioned with its `<device>.p12` (or the separate `.key` and `.crt` files).
3. When the client connects, the TLS handshake proceeds:
   - The client presents its certificate.
   - The server verifies the CA signature on the certificate using `ca.crt`.
   - The server checks that the certificate's serial number is not listed in `crl.pem`.
   - The server checks that the certificate has not expired.
   - The client proves ownership of the private key by signing a challenge — this is what prevents someone from using a stolen certificate without the corresponding key.
4. If all checks pass, the server knows the client was explicitly issued a certificate by this CA and has not been revoked.

## Revoking access

Deleting a certificate file does not revoke it — the client still holds a copy and the server has no way to know the file was deleted. To actually cut off access:

1. Run `certies revoke <client> <device>`. This adds the certificate's serial to the CRL and regenerates it.
2. Deploy the updated `crl.pem` to the server.
3. The server will now reject the revoked certificate on the next connection attempt.

The window between revocation and the server picking up the new CRL is the reason `certies renew-crl` exists — keeping the CRL validity short (e.g. 30 days) limits how stale a cached CRL can be, but requires more frequent renewal.
