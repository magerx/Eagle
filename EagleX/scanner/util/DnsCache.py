# -*- encoding:utf-8 -*-

"""
File:       DnsCache.py
Author:     magerx@paxmac.org
"""
import socket

prv_getaddrinfo = socket.getaddrinfo
dns_cache = {}  # or a weakref.WeakValueDictionary()

def new_getaddrinfo(*args):
    try:
        return dns_cache[args]
    except KeyError:
        res = prv_getaddrinfo(*args)
        dns_cache[args] = res
        return res
