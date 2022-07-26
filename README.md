![Continuous integration](https://github.com/Groestlcoin/rust-groestlcoin/workflows/Continuous%20integration/badge.svg)
[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

# Rust Groestlcoin Library

Library with support for de/serialization, parsing and executing on data
structures and network messages related to Groestlcoin.


[Documentation](https://docs.rs/groestlcoin/)

Supports (or should support)

* De/serialization of Groestlcoin protocol network messages
* De/serialization of blocks and transactions
* Script de/serialization
* Private keys and address creation, de/serialization and validation (including full BIP32 support)
* PSBT v0 de/serialization and all but the Input Finalizer role. Use [rust-miniscript](https://docs.rs/miniscript/latest/miniscript/psbt/index.html) to finalize.

For JSONRPC interaction with Groestlcoin Core, it is recommended to use
[rust-groestlcoincore-rpc](https://github.com/Groestlcoin/rust-groestlcoincore-rpc).

It is recommended to always use [cargo-crev](https://github.com/crev-dev/cargo-crev)
to verify the trustworthiness of each of your dependencies, including this one.

## Known limitations

### Consensus

This library **must not** be used for consensus code (i.e. fully validating
blockchain data). It technically supports doing this, but doing so is very
ill-advised because there are many deviations, known and unknown, between
this library and the Groestlcoin Core reference implementation. In a consensus
based cryptocurrency such as Groestlcoin it is critical that all parties are
using the same rules to validate data, and this library is simply unable
to implement the same rules as Core.

Given the complexity of both C++ and Rust, it is unlikely that this will
ever be fixed, and there are no plans to do so. Of course, patches to
fix specific consensus incompatibilities are welcome.

### Support for 16-bit pointer sizes

16-bit pointer sizes are not supported and we can't promise they will be.
If you care about them please let us know, so we can know how large the interest
is and possibly decide to support them.

## Documentation

Currently can be found on [docs.rs/groestlcoin](https://docs.rs/groestlcoin/).
Patches to add usage examples and to expand on existing docs would be extremely
appreciated.

## Contributing

Contributions are generally welcome. If you intend to make larger changes please
discuss them in an issue before PRing them to avoid duplicate work and
architectural mismatches. If you have any questions or ideas you want to discuss
please join us in
[#groestlcoin](https://web.libera.chat/?channel=#groestlcoin) on
[libera.chat](https://libera.chat).

For more information please see `./CONTRIBUTING.md`.

## Minimum Supported Rust Version (MSRV)

This library should always compile with any combination of features (minus
`no-std`) on **Rust 1.41.1** or **Rust 1.47** with `no-std`.

## Installing Rust

Rust can be installed using your package manager of choice or
[rustup.rs](https://rustup.rs). The former way is considered more secure since
it typically doesn't involve trust in the CA system. But you should be aware
that the version of Rust shipped by your distribution might be out of date.
Generally this isn't a problem for `rust-groestlcoin` since we support much older
versions than the current stable one (see MSRV section).

## Building

The library can be built and tested using [`cargo`](https://github.com/rust-lang/cargo/):

```
git clone git@github.com:rust-groestlcoin/rust-groestlcoin.git
cd rust-groestlcoin
cargo build
```

You can run tests with:

```
cargo test
```

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) for more detailed instructions.

### Building the docs

We build docs with the nightly toolchain, you may wish to use the following
shell alias to check your documentation changes build correctly.

```
alias build-docs='RUSTDOCFLAGS="--cfg docsrs" cargo +nightly rustdoc --features="$FEATURES" -- -D rustdoc::broken-intra-doc-links'
```

### Running benchmarks

We use a custom Rust compiler configuration conditional to guard the bench mark code. To run the
bench marks use: `RUSTFLAGS='--cfg=bench' cargo +nightly bench`.

## Pull Requests

Every PR needs at least two reviews to get merged. During the review phase
maintainers and contributors are likely to leave comments and request changes.
Please try to address them, otherwise your PR might get closed without merging
after a longer time of inactivity. If your PR isn't ready for review yet please
mark it by prefixing the title with `WIP: `.


## Release Notes

See [CHANGELOG.md](CHANGELOG.md).


## Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0
Universal license](LICENSE). We use the [SPDX license list](https://spdx.org/licenses/) and [SPDX
IDs](https://spdx.dev/ids/).
