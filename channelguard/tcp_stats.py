"""Windows per-connection TCP counters, with explicit availability and scope.

Uses the documented IP Helper EStats API. No adapter/process I/O substitutes.
Collection may be enabled for selected sockets only when explicitly requested;
never disables another monitor's collection or changes routing.
"""
from __future__ import annotations
import ctypes as C
import ipaddress
import os
import socket

U32 = C.c_uint32
U64 = C.c_uint64


class TcpRow(C.Structure):
    _fields_ = [(name, U32) for name in ('state', 'local', 'local_port', 'remote', 'remote_port')]


class Tcp6Row(C.Structure):
    _fields_ = [('state', U32), ('local', C.c_ubyte * 16), ('local_scope', U32),
                ('local_port', U32), ('remote', C.c_ubyte * 16),
                ('remote_scope', U32), ('remote_port', U32)]


class Data(C.Structure):
    _fields_ = [(n, U64) for n in ('DataBytesOut', 'DataSegsOut', 'DataBytesIn', 'DataSegsIn', 'SegsOut', 'SegsIn')]
    _fields_ += [(n, U32) for n in ('SoftErrors', 'SoftErrorReason', 'SndUna', 'SndNxt', 'SndMax')]
    _fields_ += [('ThruBytesAcked', U64), ('RcvNxt', U32), ('ThruBytesReceived', U64)]


class PathStats(C.Structure):
    _fields_ = [(n, U32) for n in (
        'FastRetran Timeouts SubsequentTimeouts CurTimeoutCount AbruptTimeouts PktsRetrans BytesRetrans '
        'DupAcksIn SacksRcvd SackBlocksRcvd CongSignals PreCongSumCwnd PreCongSumRtt PostCongSumRtt '
        'PostCongCountRtt EcnSignals EceRcvd SendStall QuenchRcvd RetranThresh SndDupAckEpisodes '
        'SumBytesReordered NonRecovDa NonRecovDaEpisodes AckAfterFr DsackDups SampleRtt SmoothedRtt '
        'RttVar MaxRtt MinRtt SumRtt CountRtt CurRto MaxRto MinRto CurMss MaxMss MinMss '
        'SpuriousRtoDetections').split()]


STATES = {name: i for i, name in enumerate((
    'CLOSED', 'LISTEN', 'SYN_SENT', 'SYN_RECV', 'ESTABLISHED', 'FIN_WAIT1', 'FIN_WAIT2',
    'CLOSE_WAIT', 'CLOSING', 'LAST_ACK', 'TIME_WAIT', 'DELETE_TCB'), 1)}


def make_row(connection):
    local, remote = connection['local'], connection['remote']
    a, b = ipaddress.ip_address(local[0].split('%')[0]), ipaddress.ip_address(remote[0].split('%')[0])
    state = STATES.get(connection['state'], 5)
    if a.version == 4:
        return TcpRow(state, int.from_bytes(a.packed, 'little'), socket.htons(local[1]),
                      int.from_bytes(b.packed, 'little'), socket.htons(remote[1]))
    def scope(value):
        part = value.partition('%')[2]
        return int(part) if part.isdigit() else socket.if_nametoindex(part) if part else 0
    return Tcp6Row(state, (C.c_ubyte * 16).from_buffer_copy(a.packed), scope(local[0]),
                   socket.htons(local[1]), (C.c_ubyte * 16).from_buffer_copy(b.packed),
                   scope(remote[0]), socket.htons(remote[1]))


class TcpStats:
    def __init__(self):
        self.api = C.WinDLL('iphlpapi.dll') if os.name == 'nt' else None
        if self.api:
            for prefix in ('Tcp', 'Tcp6'):
                getter = getattr(self.api, 'GetPer' + prefix + 'ConnectionEStats')
                getter.argtypes = [C.c_void_p, C.c_int, C.c_void_p, U32, U32, C.c_void_p, U32, U32, C.c_void_p, U32, U32]
                getter.restype = U32
                setter = getattr(self.api, 'SetPer' + prefix + 'ConnectionEStats')
                setter.argtypes = [C.c_void_p, C.c_int, C.c_void_p, U32, U32, U32]
                setter.restype = U32

    def read(self, connection, enable=False):
        if not self.api or connection['protocol'] != 'TCP' or not connection['remote']:
            return {'reason': '仅支持 Windows 已建立 TCP 连接'}
        try:
            row = make_row(connection)
            prefix = 'Tcp6' if isinstance(row, Tcp6Row) else 'Tcp'
            get = getattr(self.api, 'GetPer' + prefix + 'ConnectionEStats')
            set_value = getattr(self.api, 'SetPer' + prefix + 'ConnectionEStats')
            result = {}
            for kind, structure, label in ((1, Data, 'data'), (3, PathStats, 'path')):
                enabled = C.c_ubyte()
                value = structure()
                code = get(C.byref(row), kind, C.byref(enabled), 0, 1, None, 0, 0, C.byref(value), 0, C.sizeof(value))
                if not code and not enabled.value and enable:
                    flag = C.c_ubyte(1)
                    code = set_value(C.byref(row), kind, C.byref(flag), 0, 1, 0)
                    if not code:
                        code = get(C.byref(row), kind, C.byref(enabled), 0, 1, None, 0, 0, C.byref(value), 0, C.sizeof(value))
                if not code and enabled.value:
                    result[label] = {name: getattr(value, name) for name, _ in structure._fields_}
                else:
                    result[label + '_reason'] = ('Windows 错误码 ' + str(code)) if code else '该连接未启用扩展统计（通常需管理员权限）'
            return result
        except (OSError, ValueError, AttributeError) as exc:
            return {'reason': 'TCP 统计不可用：' + type(exc).__name__}
