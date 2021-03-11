#!/bin/sh

# Kali - fix "cgroup mmountpoint does not exist" when launching Docker

sudo mkdir /sys/fs/cgroup/systemd

sudo mount -t cgroup -o none,name=systemd cgroup /sys/fs/cgroup/systemd