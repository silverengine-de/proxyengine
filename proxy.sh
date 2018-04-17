#!/bin/bash
sudo ip addr add 192.168.222.3/24 dev enp7s0f1
export RUST_BACKTRACE=1
export RUST_LOG="tcp_proxy=info,proxy_engine=info,e2d2=info"
executable=`cargo build --message-format=json | jq -r 'select((.profile.test == false) and (.target.name == "proxy_engine")) | .filenames[]'`
echo $executable
sudo -E env "PATH=$PATH" $executable proxy_run.toml

