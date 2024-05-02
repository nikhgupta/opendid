#! /bin/bash

runtime="$RUNTIME"

if [ "$runtime" == "peregrine" ]; then
    ./target/release/opendid_peregrine --config ./config.yaml
    exit 0
fi

if [ "$runtime" == "spiritnet" ]; then
    ./target/release/opendid_spiritnet --config ./config.yaml
    exit 0
fi

echo "no runtime specified"
exit 1
