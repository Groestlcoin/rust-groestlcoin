# Running

To run the embedded test, first prepare your environment:

```shell
sudo ./scripts/install-deps
rustup +nightly target add thumbv7m-none-eabi
```

Then:

```shell
source ./scripts/env.sh && cargo +nightly run --target thumbv7m-none-eabi
```

Output should be something like:

```text
heap size 524288
secp buf size 66240
Seed WIF: L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3zcfamN
Address: grs1qpx9t9pzzl4qsydmhyt6ctrxxjd4ep549wseyus
```

Note that this heap size is required because of the amount of stack used by libsecp256k1 when initializing a context.

## Cleanup

After sourcing `scripts/env.sh` and _before_ building again using another target
you'll want to unset `RUSTFLAGS` otherwise you'll get linker errors.

```shell
unset RUSTFLAGS
```
