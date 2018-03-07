#!/bin/bash
sudo insmod ~/gitclones/NetBricks/3rdparty/dpdk/build/kmod/igb_uio.ko
#sudo modprobe vfio_pci
sudo insmod ~/gitclones/NetBricks/3rdparty/dpdk/build/kmod/rte_kni.ko "kthread_mode=multiple"
sudo ~/gitclones/NetBricks/3rdparty/dpdk/usertools/dpdk-devbind.py --bind igb_uio 13:00.0
sudo ~/gitclones/NetBricks/3rdparty/dpdk/usertools/dpdk-devbind.py --status
sudo ip addr add 192.168.222.3/24 dev ens192

