#!/bin/bash
# sudo ip addr add 192.168.222.3/24 dev ens34
sudo -E env "PATH=$PATH" cargo test
