import tempfile
import unittest
from pathlib import Path

import integrity


class TestIntegrity(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "a.txt").write_text("alpha")
        (self.root / "sub").mkdir()
        (self.root / "sub" / "b.txt").write_text("beta")

    def tearDown(self):
        self._tmp.cleanup()

    def test_sha256_known_value(self):
        # SHA-256 de "abc" (vecteur de test officiel)
        f = self.root / "abc.txt"
        f.write_text("abc")
        self.assertEqual(
            integrity.sha256_file(f),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_scan_uses_relative_paths(self):
        self.assertEqual(set(integrity.scan(self.root)), {"a.txt", "sub/b.txt"})

    def test_no_change(self):
        base = integrity.scan(self.root)
        self.assertEqual(integrity.compare(base, integrity.scan(self.root)),
                         {"added": [], "removed": [], "modified": []})

    def test_detects_modified_added_removed(self):
        base = integrity.scan(self.root)
        (self.root / "a.txt").write_text("alpha modifié")
        (self.root / "new.txt").write_text("nouveau")
        (self.root / "sub" / "b.txt").unlink()
        changes = integrity.compare(base, integrity.scan(self.root))
        self.assertEqual(changes["modified"], ["a.txt"])
        self.assertEqual(changes["added"], ["new.txt"])
        self.assertEqual(changes["removed"], ["sub/b.txt"])

    def test_baseline_file_is_ignored_when_inside_directory(self):
        baseline = self.root / "baseline.json"
        baseline.write_text("{}")
        self.assertNotIn("baseline.json", integrity.scan(self.root, ignore=[baseline]))

    def test_save_and_load_baseline(self):
        files = integrity.scan(self.root)
        path = self.root.parent / "baseline_test.json"
        integrity.save_baseline(files, path, self.root)
        try:
            self.assertEqual(integrity.load_baseline(path), files)
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
