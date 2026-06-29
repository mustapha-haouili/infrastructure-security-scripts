import hashlib
import json
import re
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseBundleMetadataTests(unittest.TestCase):
    def test_shell_release_bundle_has_manifest_hashes_and_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    "bash",
                    "scripts/release/create_release_bundle.sh",
                    "--output-dir",
                    tmp,
                    "--version",
                    "test-release",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )

            self.assertIn("Release archive:", result.stdout)
            archive_path = Path(tmp) / "secureinfra-release-test-release.zip"
            self.assertTrue(archive_path.exists())

            with zipfile.ZipFile(archive_path) as archive:
                names = set(archive.namelist())
                manifest = json.loads(archive.read("RELEASE-MANIFEST.json").decode("utf-8"))
                checksums = archive.read("SHA256SUMS.txt").decode("ascii")

                self.assertEqual(manifest["version"], "test-release")
                self.assertRegex(manifest["generated_at_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
                self.assertIn("README.md", names)
                self.assertIn("docs/release-integrity.md", names)
                self.assertIn("scripts/release/create_release_bundle.sh", names)

                manifest_paths = {item["path"] for item in manifest["files"]}
                self.assertEqual(manifest["file_count"], len(manifest_paths))
                self.assertIn("README.md", manifest_paths)
                self.assertNotIn("RELEASE-MANIFEST.json", manifest_paths)
                self.assertNotIn("SHA256SUMS.txt", manifest_paths)

                blocked_patterns = [
                    r"(^|/)\.git(/|$)",
                    r"(^|/)\.codex(/|$)",
                    r"^reports(/|$)",
                    r"^SecureInfra_AI/reports(/|$)",
                    r"\.local\.",
                    r"\.(zip|7z|rar|tar|tgz|gz|pfx|p12|pem|key|der|kdbx|sqlite|db|bak|tmp|pyc)$",
                ]
                for path in manifest_paths:
                    self.assertFalse(path.startswith("/") or path.startswith("\\"))
                    self.assertNotIn("..", Path(path).parts)
                    for pattern in blocked_patterns:
                        self.assertIsNone(re.search(pattern, path, flags=re.IGNORECASE), path)

                readme_entry = next(item for item in manifest["files"] if item["path"] == "README.md")
                readme_payload = archive.read("README.md")
                self.assertEqual(readme_entry["size"], len(readme_payload))
                self.assertEqual(readme_entry["sha256"], hashlib.sha256(readme_payload).hexdigest())
                self.assertIn(f"{readme_entry['sha256']}  README.md\n", checksums)


if __name__ == "__main__":
    unittest.main()
