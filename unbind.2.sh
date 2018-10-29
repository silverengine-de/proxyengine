#!/bin/bash
bricksDir=~/work/NetBricks
sudo ip link set ens2f0 down
sudo $bricksDir/3rdparty/dpdk/usertools/dpdk-devbind.py --bind i40e 0a:00.0
sudo $bricksDir/3rdparty/dpdk/usertools/dpdk-devbind.py --status
nmcli dev set ens2f0 managed no
sudo ip addr flush dev ens2f0
sudo ip addr add 192.168.222.8/24 dev ens2f0
sudo ip link set ens2f0 up
ip addr show dev ens2f0

