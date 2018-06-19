#!/usr/bin/env python3

ips_all = open("all.list").read().splitlines()
ips_alive = open("alive.list").read().splitlines()

for ip in ips_all:
    if not ip in ips_alive:
        print(ip)
