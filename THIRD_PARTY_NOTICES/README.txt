ChannelGuard 0.1.0 — third-party notices

Application source: source/ (GPL-3.0)
Mihomo v1.19.33: GPL-3.0; unmodified upstream source archive and release digest are in _internal/vendor/.
Source: https://github.com/MetaCubeX/mihomo/tree/v1.19.33
Wintun 0.14.1: signed AMD64 DLL, redistribution terms in WINTUN.txt.
Source and signed distribution: https://www.wintun.net/
Chromium / Chrome for Testing: BSD-style and component-specific licenses, see CHROMIUM-CREDITS.html.
Source: https://chromium.googlesource.com/chromium/src/
Playwright 1.59.0: Apache-2.0, see playwright/.
Source: https://github.com/microsoft/playwright-python/tree/v1.59.0
PySide6 / Qt 6.12.0: LGPL-3.0 / GPL-3.0, see PySide6-Essentials/ and shiboken6/.
These libraries are dynamically linked in _internal/PySide6 and may be replaced with compatible builds.
Sources: https://code.qt.io/cgit/pyside/pyside-setup.git/ and https://code.qt.io/cgit/qt/qtbase.git/
Python: PSF license (PYTHON-LICENSE.txt).
Other component licenses are retained in their corresponding subdirectories.

No changes were made to Mihomo, Wintun, Chromium, Qt, Python or Playwright upstream source code.
Rebuilding the application: source/build.py with source/requirements.txt plus Pillow.
The Chromium and Mihomo executable files are external processes; Qt remains dynamically linked.
