#!/bin/bash
export RUST_BACKTRACE=1
export RUST_LOG="tcp_proxy=info,proxy_engine=debug,e2d2=debug"
executable=`cargo build $1 --message-format=json | jq -r 'select((.profile.test == false) and (.target.name == "proxy_engine")) | .filenames[]'`
echo $executable
sudo -E env "PATH=$PATH" $executable proxy_run.toml

