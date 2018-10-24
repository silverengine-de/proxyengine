#!/bin/bash
bricksDir=~/work/NetBricks
sudo ip link set enp7s0f0 down
sudo modprobe vfio_pci
sudo insmod $bricksDir/3rdparty/dpdk/build/kmod/rte_kni.ko "kthread_mode=multiple"
sudo $bricksDir/3rdparty/dpdk/usertools/dpdk-devbind.py --bind vfio-pci 07:00.0
sudo $bricksDir/3rdparty/dpdk/usertools/dpdk-devbind.py --status
sudo ip addr add 192.168.222.32/24 dev enp7s0f1
sudo ip link set enp7s0f1 up


