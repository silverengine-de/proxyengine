#!/bin/bash
sudo ip addr add 192.168.222.3/24 dev enp7s0f1
export RUST_LOG="tcp_proxy=info,proxy_engine=debug,e2d2=info"
executable=`cargo test --no-run --message-format=json | jq -r 'select((.profile.test == true) and (.target.name == "tcp_proxy")) | .filenames[]'`
echo $executable
sudo -E env "PATH=$PATH" $executable --nocapture

