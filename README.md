RFC2136 for `libdns`
=======================

[![godoc reference](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/libdns/rfc2136)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [RFC2136](https://tools.ietf.org/html/rfc2136).

## Authenticating

This package can optionally use **TSIG authentication**, which uses HMAC to sign the requests with a secret key. Using TSIG authentication is _strongly recommended_, as otherwise you would be allowing anyone who can access your RFC2136-supporting DNS server to make DNS updates.

### Generate a TSIG key

If you are managing your own DNS server, you may use the [`tsig-keygen`](https://manpages.debian.org/testing/bind9/tsig-keygen.8.en.html) command, which comes with `bind9`, to generate a key that can be used with this provider.

```bash
$ keyname=libdns keyfile=libdns.key; tsig-keygen $keyname > $keyfile
```

This will generate a key with the name `libdns` with the default algorithm `hmac-sha256`. The file will look something like this:

```text
key "libdns" {
        algorithm hmac-sha256;
        secret "rfXPtMx3r1kl0QzpuwBtexbl2pUJesmZc35UcvzGdwE=";
};
```

You can then configure `bind9`, if that's your DNS server of choice, to use this key file with the `allow-transfer` option of the zone configuration.

```
zone "sub.example.org" {
    ...
    allow-transfer {
        key "libdns";
    };
    update-policy {
        grant libdns zonesub ANY;
    };
    ...
};
```