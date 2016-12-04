from collections import namedtuple
from enum import Enum
import ctypes as ct
from socket import inet_ntop, AF_INET6

TASK_COMM_LEN = 16      # linux/sched.h

class Quartet(object):
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port

    def __str__(self):
        return '{0}:{1} -> {2}:{3}'.format(
            self.src_ip, self.src_port, self.dst_ip, self.dst_port)

class BaseEvent(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong * 2),
        ("daddr", ct.c_ulonglong * 2),
        ("event_type", ct.c_ulonglong),
        ("ports", ct.c_ulonglong),
        ("delta_us", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN),
        # Throughput
        ("rx_b", ct.c_ulonglong),
        ("tx_b", ct.c_ulonglong),
        ("segs_out", ct.c_ulonglong),
        ("segs_in", ct.c_ulonglong),
        ("rcv_tstamp", ct.c_ulonglong),
        ("lsndtime", ct.c_ulonglong),
        # Windowing
        ("snd_wl1", ct.c_ulonglong),
        ("snd_wnd", ct.c_ulonglong),
        ("max_window", ct.c_ulonglong),
        ("mss_cache", ct.c_ulonglong),
        ("window_clamp", ct.c_ulonglong),
        ("rcv_ssthresh", ct.c_ulonglong),
        ("packets_out", ct.c_ulonglong),
        ("retrans_out", ct.c_ulonglong),
        ("max_packets_out", ct.c_ulonglong),
        ("max_packets_seq", ct.c_ulonglong),
        # RTT
        ("srtt_us", ct.c_ulonglong),
        ("mdev_us", ct.c_ulonglong),
        ("mdev_max_us", ct.c_ulonglong),
        # Congestion
    ]


class Event(object):
    def __init__(self, data):
        event = ct.cast(data, ct.POINTER(BaseEvent)).contents
        q = Quartet(
            inet_ntop(AF_INET6, event.saddr),
            inet_ntop(AF_INET6, event.daddr),
            event.ports >> 32,
            event.ports & 0xffffffff,
        )
        self.quartet = q
        self.base_event = event
        if event.event_type == 0:
            self.action = 'register'
        elif event.event_type == 1:
            self.action = 'unregister'
        elif event.event_type == 2:
            self.action = 'publish'
