#!/bin/sh

set -ex

CRATES="groestlcoin hashes internals"

for crate in ${CRATES}
do
    (
        cd "$crate"
        ./contrib/test.sh
    )
done

exit 0
