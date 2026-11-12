import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from channelguard.engine import Engines
from channelguard.storage import new_channel

class CoreIsolation(unittest.TestCase):
    def test_distinct_stable_paths_and_idle_core_update(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'packaged-core.exe';source.write_bytes(b'version-one')
            engine=Engines.__new__(Engines);engine.store=SimpleNamespace(root=root);engine.core=source;engine.active={}
            a,b=new_channel()['id'],new_channel()['id']
            first,second=engine.prepare_core(a),engine.prepare_core(b)
            self.assertNotEqual(first,second);self.assertEqual(engine.prepare_core(a),first)
            self.assertEqual(first.read_bytes(),source.read_bytes())
            source.write_bytes(b'version-two');engine.active[a]={}
            engine.prepare_core(a);self.assertEqual(first.read_bytes(),b'version-one')
            engine.active.clear();engine.prepare_core(a);self.assertEqual(first.read_bytes(),b'version-two')
            self.assertEqual(second.read_bytes(),b'version-one')

    def test_invalid_identity_cannot_escape_data_directory(self):
        engine=Engines.__new__(Engines);engine.store=SimpleNamespace(root=Path('data'))
        for identity in ('../outside','a'*31,'z'*32):
            with self.assertRaises(ValueError):engine.core_path(identity)
