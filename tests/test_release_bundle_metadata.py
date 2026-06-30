import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def candidate_bash_paths():
    candidates = []
    env_bash = os.environ.get("BASH")
    if env_bash:
        candidates.append(env_bash)
    path_bash = shutil.which("bash")
    if os.name == "nt":
        candidates.extend(
            [
                r"C:\Program Files\Git\bin\bash.exe",
                r"C:\Program Files\Git\usr\bin\bash.exe",
                r"C:\Program Files (x86)\Git\bin\bash.exe",
                r"C:\Program Files (x86)\Git\usr\bin\bash.exe",
            ]
        )
        if path_bash:
            candidates.append(path_bash)
    else:
        if path_bash:
            candidates.append(path_bash)
        candidates.append("/bin/bash")

    unique = []
    seen = set()
    for candidate in candidates:
        if not candidate:
            continue
        key = str(candidate).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def usable_bash():
    for candidate in candidate_bash_paths():
        if os.name == "nt" and "system32\\bash.exe" in str(candidate).lower():
            continue
        if not Path(candidate).exists() and shutil.which(candidate) is None:
            continue
        try:
            result = subprocess.run(
                [candidate, "-lc", "printf ok"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode != 0 or result.stdout != "ok":
            continue
        if os.name == "nt":
            try:
                cygpath_result = subprocess.run(
                    [candidate, "-lc", "command -v cygpath >/dev/null 2>&1"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=10,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if cygpath_result.returncode != 0:
                continue
        return candidate
    raise unittest.SkipTest("No usable Git Bash/MSYS bash executable was found for the shell release bundle test.")


def run_bash_script(bash_executable, args):
    command = " ".join(shlex.quote(arg) for arg in args)
    env = os.environ.copy()
    env["PYTHON_BIN"] = sys.executable
    return subprocess.run(
        [bash_executable, "-lc", command],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def cleanup_malformed_repo_outputs(temp_leaf, existing_top_level):
    protected = {
        ".git",
        ".github",
        ".codex",
        "SecureInfra_AI",
        "docs",
        "examples",
        "schemas",
        "scripts",
        "tests",
        "reports",
        "backups",
    }
    for child in ROOT.iterdir():
        if child.name in existing_top_level or child.name in protected:
            continue
        if not child.exists():
            continue
        if child.is_file():
            if temp_leaf in child.name:
                child.unlink()
            continue
        if not child.is_dir():
            continue
        child_text = str(child)
        contains_temp_leaf = temp_leaf in child_text
        if not contains_temp_leaf:
            try:
                contains_temp_leaf = any(temp_leaf in str(path) for path in child.rglob("*"))
            except OSError:
                contains_temp_leaf = False
        if contains_temp_leaf:
            shutil.rmtree(child, ignore_errors=True)


def malformed_repo_outputs(temp_leaf, existing_top_level):
    matches = []
    for child in ROOT.iterdir():
        if child.name in existing_top_level:
            continue
        if temp_leaf in str(child):
            matches.append(child)
            continue
        if child.is_dir():
            try:
                if any(temp_leaf in str(path) for path in child.rglob("*")):
                    matches.append(child)
            except OSError:
                pass
    return matches


class ReleaseBundleMetadataTests(unittest.TestCase):
    def test_shell_release_bundle_has_manifest_hashes_and_exclusions(self):
        bash_executable = usable_bash()
        with tempfile.TemporaryDirectory(prefix="secureinfra-release-test-") as tmp:
            existing_top_level = {child.name for child in ROOT.iterdir()}
            temp_leaf = Path(tmp).name
            self.addCleanup(cleanup_malformed_repo_outputs, temp_leaf, existing_top_level)

            result = run_bash_script(
                bash_executable,
                [
                    "scripts/release/create_release_bundle.sh",
                    "--output-dir",
                    tmp,
                    "--version",
                    "test-release",
                ],
            )

            self.assertIn("Release archive:", result.stdout)
            archive_path = Path(tmp) / "secureinfra-release-test-release.zip"
            self.assertTrue(archive_path.exists())
            self.assertEqual(archive_path.parent.resolve(), Path(tmp).resolve())
            self.assertEqual(malformed_repo_outputs(temp_leaf, existing_top_level), [])

            with zipfile.ZipFile(archive_path) as archive:
                names = set(archive.namelist())
                manifest = json.loads(archive.read("RELEASE-MANIFEST.json").decode("utf-8"))
                checksums = archive.read("SHA256SUMS.txt").decode("ascii")

                self.assertEqual(manifest["version"], "test-release")
                self.assertRegex(manifest["generated_at_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
                self.assertIn("RELEASE-MANIFEST.json", names)
                self.assertIn("SHA256SUMS.txt", names)
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
