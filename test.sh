#!/bin/bash
set -e
#we flush the ARP cache because outdated ARP entries may let tests fail
sudo ip -s -s neigh flush all

if [ $# -ge 1 ]; then
    TASK=$1
else
    TASK=all
fi

case $TASK in
    test_rfs_ip)
        export RUST_LOG="tcp_proxy=info,test_tcp_proxy=info,e2d2=info"
        export RUST_BACKTRACE=1
        executable=`cargo test $2 --no-run --message-format=json --test test_tcp_proxy | jq -r 'select((.profile.test == true) and (.target.name == "test_tcp_proxy")) | .filenames[]'`
        echo $executable
        echo ./tests/test_rfs_ip.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    test_rfs_ip.2)
        export RUST_LOG="tcp_proxy=info,test_tcp_proxy=info,e2d2=info"
        export RUST_BACKTRACE=1
        executable=`cargo test $2 --no-run --message-format=json --test test_tcp_proxy | jq -r 'select((.profile.test == true) and (.target.name == "test_tcp_proxy")) | .filenames[]'`
        echo $executable
        echo ./tests/test_rfs_ip.2.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    test_rfs_port)
        export RUST_LOG="tcp_proxy=info,test_tcp_proxy=info,e2d2=info"
        export RUST_BACKTRACE=1
        executable=`cargo test $2 --no-run --message-format=json --test test_tcp_proxy | jq -r 'select((.profile.test == true) and (.target.name == "test_tcp_proxy")) | .filenames[]'`
        echo $executable
        echo ./tests/test_rfs_port.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    timeout)
        export RUST_BACKTRACE=1
        export RUST_LOG="tcp_proxy=info,timeout=info,e2d2=info"
        executable=`cargo test $2 --no-run --message-format=json --test timeout | jq -r 'select((.profile.test == true) and (.target.name == "timeout")) | .filenames[]'`
        echo $executable
        echo ./tests/timeout.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    timeout.2)
        export RUST_BACKTRACE=1
        export RUST_LOG="tcp_proxy=info,timeout=info,e2d2=info"
        executable=`cargo test $2 --no-run --message-format=json --test timeout | jq -r 'select((.profile.test == true) and (.target.name == "timeout")) | .filenames[]'`
        echo $executable
        echo ./tests/timeout.2.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    client_syn_fin)
        export RUST_LOG="tcp_proxy=info,client_syn_fin=info,e2d2=info"
        executable=`cargo test $2 --no-run --message-format=json --test client_syn_fin | jq -r 'select((.profile.test == true) and (.target.name == "client_syn_fin")) | .filenames[]'`
        echo $executable
        echo ./tests/client_syn_fin.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    client_syn_fin.2)
        export RUST_LOG="tcp_proxy=info,client_syn_fin=info,e2d2=info"
        executable=`cargo test $2 --no-run --message-format=json --test client_syn_fin | jq -r 'select((.profile.test == true) and (.target.name == "client_syn_fin")) | .filenames[]'`
        echo $executable
        echo ./tests/client_syn_fin.2.toml > tests/toml_file.txt
        sudo -E env "PATH=$PATH" $executable --nocapture
        ;;
    all)
        ./test.sh test_rfs_ip $2
        ./test.sh test_rfs_port $2
        ./test.sh client_syn_fin $2
        #run timeout as last test, as it does not close all sockets, otherwise we need to wait until Linux times all sockets out
        ./test.sh timeout $2
        ;;
esac



