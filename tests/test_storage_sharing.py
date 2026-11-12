import tempfile,threading,time,unittest
from pathlib import Path
from channelguard.storage import atomic_write

class WindowsSharingTests(unittest.TestCase):
    def test_atomic_writer_waits_for_existing_reader_without_partial_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'status.json';path.write_bytes(b'old complete value')
            failures=[];done=threading.Event()
            def writer():
                try:atomic_write(path,b'new complete value')
                except Exception as exc:failures.append(exc)
                finally:done.set()
            with path.open('rb') as reader:
                thread=threading.Thread(target=writer);thread.start();time.sleep(.05)
                self.assertEqual(reader.read(),b'old complete value')
            self.assertTrue(done.wait(2));thread.join(2)
            self.assertFalse(failures);self.assertEqual(path.read_bytes(),b'new complete value')
