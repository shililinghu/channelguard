"""Current-user Windows sign-in startup; never requires administrator access."""
from __future__ import annotations
from pathlib import Path
import subprocess
import sys
import winreg

RUN_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'
VALUE_NAME = 'ChannelGuard'


def startup_enabled():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            command, kind = winreg.QueryValueEx(key, VALUE_NAME)
            return kind == winreg.REG_SZ and bool(command)
    except FileNotFoundError:
        return False


def set_startup(enabled, data_root):
    if enabled:
        executable = Path(sys.executable).resolve()
        args = [str(executable)]
        if not getattr(sys, 'frozen', False):
            pythonw = executable.with_name('pythonw.exe')
            if pythonw.is_file():
                args[0] = str(pythonw)
            args.append(str(Path(__file__).resolve().parents[1] / 'main.py'))
        args += ['--data-dir', str(Path(data_root).resolve())]
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, subprocess.list2cmdline(args))
    else:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, VALUE_NAME)
        except FileNotFoundError:
            pass
