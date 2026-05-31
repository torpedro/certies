# TLS client authentication handshake

This document explains how the certificates managed by `certies` are used during
a TLS handshake, with more detail on the cryptographic checks involved.

## The pieces

`certies` creates three important cryptographic objects:

- A CA private key and CA certificate.
- A client private key.
- A client certificate containing the client's public key, signed by the CA.

The CA private key signs certificates. The client private key proves possession
during a TLS connection. The server only needs the CA certificate, the current
CRL, and the certificate chain presented by the client.

## Public key signatures

A digital signature scheme has three core operations:

```text
(public_key, private_key) = KeyGen()
signature = Sign(private_key, message)
valid = Verify(public_key, message, signature)
```

The private key creates signatures. The public key verifies them. Verification
does not reveal the private key and cannot create new signatures.

In this project, generated client keys are ECDSA P-256. The generated CA key is
also ECDSA P-256, though an imported RSA CA can also sign client certificates.

## Certificate signing

A certificate is a signed statement. For a client certificate, the statement is
roughly:

```text
subject: CN=alice/laptop
public key: client_public_key
serial: 02
validity: not_before..not_after
usage: client authentication
issuer: certies CA
```

The CA signs the certificate's TBSCertificate, meaning "to be signed
certificate". The simplified operation is:

```text
digest = SHA256(TBSCertificate)
signature = Sign(ca_private_key, digest)
```

The final certificate contains:

```text
TBSCertificate
signature_algorithm
signature
```

When the server receives this certificate, it verifies:

```text
digest = SHA256(TBSCertificate)
Verify(ca_public_key, digest, signature)
```

The `ca_public_key` comes from `ca.crt`, which the server has been configured to
trust. If verification succeeds, the server knows the CA signed the certificate
contents. That includes the client's public key, subject, serial, validity
dates, and usage extensions.

## RSA signatures, briefly

For RSA signing, the CA private key contains a private exponent `d`, modulus
`n`, and related CRT values. The public key contains exponent `e` and the same
modulus `n`.

Very simplified textbook RSA signing looks like:

```text
s = m^d mod n
m = s^e mod n
```

Real TLS certificates do not sign raw messages this way. They sign a structured
hash encoding, normally using RSA-PSS or PKCS#1 v1.5 depending on the
certificate signature algorithm. The important relationship is still that only
the private exponent can produce a signature that verifies with the public
exponent.

An RSA CA can sign a client certificate containing an ECDSA public key. The CA
signature algorithm and the client's own key algorithm are separate.

## ECDSA signatures, briefly

ECDSA uses elliptic curve group arithmetic. For P-256, there is a standard
generator point `G` of large prime order `n`.

A private key is a random integer:

```text
d where 1 <= d < n
```

The public key is an elliptic curve point:

```text
Q = dG
```

Computing `Q` from `d` is easy. Recovering `d` from `Q` is intended to be
computationally infeasible.

To sign a message hash `z`, ECDSA chooses a fresh secret nonce `k` and computes:

```text
R = kG
r = R.x mod n
s = k^-1 * (z + r*d) mod n
signature = (r, s)
```

Verification checks the signature using only the public key:

```text
w = s^-1 mod n
u1 = z*w mod n
u2 = r*w mod n
X = u1*G + u2*Q
valid if X.x mod n == r
```

Substituting `Q = dG` shows why this works:

```text
X = (z/s)G + (r/s)dG
X = ((z + r*d)/s)G
```

Since:

```text
s = k^-1 * (z + r*d)
```

then:

```text
(z + r*d)/s = k
```

So:

```text
X = kG = R
```

and `X.x mod n` matches `r`.

The nonce `k` must never be reused with the same private key. Reusing `k` across
two signatures can reveal the private key.

## Server certificate authentication

Most TLS handshakes authenticate the server first.

The server sends its certificate chain. The client verifies:

- The chain leads to a trusted root CA.
- Each certificate signature verifies against its issuer's public key.
- The server certificate is valid for the hostname being contacted.
- The certificate is within its validity period.
- The certificate has appropriate key usage for server authentication.
- Revocation checks pass if configured.

This prevents a client from sending secrets to an unauthenticated server.

## Client certificate authentication

With mutual TLS, the server also asks the client for a certificate. The client
sends its certificate chain and then proves it owns the matching private key.

The server verifies the client certificate:

- The certificate was signed by a trusted CA, usually `ca.crt`.
- The certificate is within its validity period.
- The certificate has `clientAuth` extended key usage.
- The certificate serial is not present in `crl.pem`.
- The certificate subject maps to an allowed identity, such as `alice/laptop`.

The CA signature proves the certificate was issued by the CA. It does not prove
the connecting client has the private key. That is handled by the TLS
CertificateVerify message.

## CertificateVerify

During the handshake, both sides build a transcript of handshake messages. A
transcript hash is computed over those bytes:

```text
transcript_hash = Hash(ClientHello || ServerHello || ... || Certificate)
```

For client authentication, the client signs a context-specific value derived
from this transcript hash:

```text
signature = Sign(client_private_key, context || transcript_hash)
```

The exact context string and formatting are defined by the TLS version. TLS 1.3
uses domain separation so that a signature created for one handshake purpose
cannot be replayed as another kind of signature.

The server verifies:

```text
Verify(client_public_key, context || transcript_hash, signature)
```

The `client_public_key` comes from the client certificate. If this verification
succeeds, the server knows the peer has the private key corresponding to the
public key in the CA-signed certificate.

## Why the transcript is signed

The client does not merely sign a random challenge. It signs the handshake
transcript, which binds the proof to this exact connection.

That means the signature covers, through the transcript hash, important
handshake choices such as:

- Client and server random values.
- Protocol version negotiation.
- Cipher suite negotiation.
- Key exchange messages.
- Certificates sent so far.

This prevents an attacker from copying a CertificateVerify signature from one
connection and using it in another connection with different parameters.

## Key exchange and traffic keys

Certificate signatures authenticate identities. They do not directly encrypt the
application data.

Modern TLS uses ephemeral Diffie-Hellman key exchange, usually ECDHE. In
simplified elliptic curve Diffie-Hellman:

```text
client_private = a
client_public = aG

server_private = b
server_public = bG
```

Each side computes the same shared point:

```text
client computes: a(server_public) = a(bG) = abG
server computes: b(client_public) = b(aG) = abG
```

An observer sees `aG` and `bG`, but cannot feasibly compute `abG`.

TLS feeds the shared secret into a key derivation function along with handshake
context:

```text
traffic_keys = KDF(shared_secret, transcript_hash, labels)
```

Those traffic keys are then used with symmetric encryption, such as AES-GCM or
ChaCha20-Poly1305, to protect application data.

## Finished messages

After certificate verification and key exchange, each side sends a Finished
message. This is a MAC over the handshake transcript using keys derived from the
handshake secret:

```text
finished_key = KDF(handshake_secret, "finished")
verify_data = HMAC(finished_key, transcript_hash)
```

If either side has a different transcript or derived a different secret, the
Finished verification fails. This catches tampering with the handshake.

## Where revocation fits

Revocation is not a signature check. It is a policy check.

The CRL is itself signed by the CA:

```text
crl_signature = Sign(ca_private_key, CRL_data)
```

The server verifies the CRL signature with the CA public key, checks that the
CRL is currently valid, and then checks whether the client's certificate serial
appears in the revoked list.

In `certies`, `index.txt` is the durable revocation database. `crl.pem` is the
signed artifact generated from it for servers to consume.

## Summary

Mutual TLS combines several separate checks:

- CA signatures prove certificates were issued by trusted authorities.
- Certificate validity and key usage checks constrain how certificates may be
  used.
- CRL checks reject certificates that were revoked before expiry.
- CertificateVerify proves the peer has the private key for its certificate.
- Diffie-Hellman establishes fresh traffic keys.
- Finished messages prove both sides saw the same handshake and derived the same
  secrets.

Together, these checks let a server authenticate a client as a holder of a
specific CA-issued certificate, not merely as someone who copied a certificate
file.
