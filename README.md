**DEVELOPER INSTRUCTIONS:**

This repo is a template for developers to use when creating new
[libdns](https://github.com/libdns/libdns) provider implementations.

Be sure to update:

- [X] The package name
- [X] The Go module name in go.mod
- [X] The latest `libdns/libdns` version in go.mod
- [ ] All comments and documentation, including README below and godocs
- [X] License (must be compatible with Apache/MIT)
- [ ] All "TODO:"s is in the code
- [ ] All methods that currently do nothing
- [ ] Remove this section from the readme before publishing.

---

`nfsn` for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/nfsn)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for
[nearlyfreespeech.net](https://www.nearlyfreespeech.net), allowing you to manage DNS records hosted
there.

TODO: Show how to configure and use. Explain any caveats.

## Reference

_Note: these require an NFSN account to access._

* [NFSN API Introduction](https://members.nearlyfreespeech.net/wiki/API/Introduction)
* [NFSN API Reference](https://members.nearlyfreespeech.net/wiki/API/Reference)
