# certies

A command-line tool for managing SSL client certificates used for user authentication. It maintains a local Certificate Authority, issues and revokes client certificates, and keeps a Certificate Revocation List (CRL) up to date.

## Building

Requires Rust and system OpenSSL headers (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on Fedora).

```sh
cargo build --release
```

The binary is placed at `target/release/certies`. To install it to `~/.cargo/bin`:

```sh
cargo install --path .
```

## Store layout

All data is stored in `~/.certies/` by default. Every command accepts `--store <path>` to use a different location.

```
~/.certies/
  serial                              # next certificate serial number (hex)
  crlnumber                           # next CRL number (hex)
  index.txt                           # OpenSSL-style issued/revoked certificate database
  ca/
    ca.key                            # CA private key (mode 0600)
    ca.crt                            # CA certificate (PEM)
  crl/
    crl.pem                           # Certificate Revocation List
  clients/
    <client>/
      <device>/
        <device>.key                  # client private key (mode 0600)
        <device>.crt                  # client certificate (PEM)
        <device>.p12                  # PKCS#12 bundle: key + cert + CA chain (mode 0600)
```

## Commands

### `init-ca`

Initialises a new Certificate Authority. Prompts for the CA name and validity period interactively; both can also be passed as flags.

```sh
certies init-ca
certies init-ca --name "My CA" --validity-days 3650
```

An initial (empty) CRL is generated automatically.

### `new`

Issues a certificate for a client/device pair. Creates the directory `clients/<client>/<device>/` containing the key, certificate, and a PKCS#12 bundle.

```sh
certies new alice laptop
certies new alice laptop --validity-days 365
```

Two passwords are collected interactively if not supplied as flags:

- **Key password** — encrypts the private key with AES-256-CBC. Press Enter to leave the key unencrypted.
- **P12 password** — encrypts the PKCS#12 bundle. Required (cannot be empty).

```sh
certies new alice laptop --key-password secret --p12-password secret
```

### `revoke`

Revokes a certificate and immediately regenerates the CRL.

```sh
certies revoke alice laptop
```

### `renew-crl`

Regenerates the CRL with a new validity window without changing which certificates are revoked.

```sh
certies renew-crl
certies renew-crl --validity-days 90
```

### `status`

Prints a summary of the CA, CRL, and all client certificates — including validity dates and revocation status. Valid entries are shown in green, problematic ones in red.

```sh
certies status
```

### `reset`

Deletes all certificates and resets the store. Asks for confirmation before proceeding.

```sh
certies reset
```

## Global flag

All commands accept `--store <path>` to target a store other than `~/.certies/`:

```sh
certies --store /etc/certies status
certies --store /etc/certies new bob phone
```
