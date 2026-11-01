"""Shared relay admission limits. All counters belong to the asyncio event loop."""
import collections
import re

from aiohttp import web

STATE = web.AppKey("minidesk", dict)

MAX_MESSAGE = 8 << 20
MAX_CONTROL = 64 << 10
PAIR_TIMEOUT = 10
HOST_ID = re.compile(r"[A-Za-z0-9_-]{8,64}\Z")
SESSION_ID = re.compile(rb"[A-Za-z0-9_-]{24}\Z")


class Admission:
    def __init__(self, total=128, per_ip=16, per_host=8):
        self.total, self.per_ip, self.per_host = total, per_ip, per_host
        self.count = 0
        self.ips, self.hosts = collections.Counter(), collections.Counter()

    def acquire(self, ip, host=None):
        if (self.count >= self.total or self.ips[ip] >= self.per_ip
                or host is not None and self.hosts[host] >= self.per_host):
            return None
        self.count += 1
        self.ips[ip] += 1
        if host is not None:
            self.hosts[host] += 1
        released = False

        def release():
            nonlocal released
            if released:
                return
            released = True
            self.count -= 1
            self.ips[ip] -= 1
            if not self.ips[ip]:
                del self.ips[ip]
            if host is not None:
                self.hosts[host] -= 1
                if not self.hosts[host]:
                    del self.hosts[host]

        return release
