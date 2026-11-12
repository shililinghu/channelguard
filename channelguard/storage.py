"""Windows-user-bound encrypted settings; no credentials shipped in the app."""
from __future__ import annotations
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import tempfile
import time
import uuid

class Blob(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]

def dpapi(data: bytes, decrypt=False) -> bytes:
    if os.name != 'nt':
        raise RuntimeError('本版本仅支持 Windows，拒绝以明文保存凭据。')
    buf = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
    target = Blob()
    api = ctypes.windll.crypt32.CryptUnprotectData if decrypt else ctypes.windll.crypt32.CryptProtectData
    if not api(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(target.pbData)

def atomic_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.cg-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Windows readers/AV may briefly hold an existing file without DELETE
        # sharing. Keep the previous complete value until its handle is released.
        for attempt in range(30):
            try:os.replace(temporary,path);break
            except PermissionError:
                if attempt==29:raise
                time.sleep(.01)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

def new_channel(name='新信道'):
    return dict(id=uuid.uuid4().hex, name=name, interface='', node=None,
                timezone='America/Los_Angeles', locale='en-US', geo='deny',
                latitude=34.0522, longitude=-118.2437, expected_country='',
                doh='https://1.1.1.1/dns-query', bootstrap_doh='https://1.1.1.1/dns-query', apps=[], notes='')

class Store:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = root / 'settings.dpapi'
        self.data = {'schema': 1, 'channels': [], 'firewall_guards': {}}
        if self.path.exists():
            try:
                self.data = json.loads(dpapi(self.path.read_bytes(), True))
                if self.data.get('schema') != 1 or not isinstance(self.data.get('channels'), list):
                    raise ValueError('配置版本不受支持')
            except Exception as exc:
                raise RuntimeError('配置无法解密或已损坏。原文件已保留，请使用同一 Windows 用户打开。') from exc
        else:
            c = new_channel('本地信道')
            c.update(timezone='Asia/Shanghai', locale='zh-CN')
            self.data['channels'].append(c)
            self.save()

    def save(self):
        atomic_write(self.path, dpapi(json.dumps(self.data, ensure_ascii=False).encode('utf-8')))

    def channel(self, channel_id):
        return next(c for c in self.data['channels'] if c['id'] == channel_id)

    def backup(self, destination):
        self.save()
        atomic_write(Path(destination), self.path.read_bytes())
