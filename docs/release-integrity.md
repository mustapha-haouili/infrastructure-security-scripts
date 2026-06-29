# Release Integrity

This repository publishes public defensive release artifacts only. Release
bundles must not contain customer data, generated customer reports, raw
evidence, private commercial delivery files, local configuration, certificates,
secrets, credentials, tokens, or private key material.

The release bundle scripts package selected public files from:

- Root project documentation and metadata such as `README.md`, `CHANGELOG.md`,
  `LICENSE`, `VERSION`, and `AGENTS.md`
- `scripts/`
- `docs/`
- `schemas/`
- `examples/`
- `SecureInfra_AI/`

The scripts exclude repository internals and generated or private material,
including `.git`, `.codex`, `.agents`, `reports/`, `SecureInfra_AI/reports/`,
backup directories, temporary directories, local configuration files, archives,
private-key/certificate formats, database files, and common credential/token
file patterns.

## PowerShell Usage

Create a bundle using the version in `VERSION`:

```powershell
.\scripts\release\New-SecureInfraReleaseBundle.ps1
```

Create a bundle in a specific output directory:

```powershell
.\scripts\release\New-SecureInfraReleaseBundle.ps1 -OutputDirectory .\dist
```

Create a bundle with an explicit version and replace an existing local output:

```powershell
.\scripts\release\New-SecureInfraReleaseBundle.ps1 -Version 1.2.0-beta.1 -OutputDirectory .\dist -Force
```

## Shell Usage

Create a bundle using the version in `VERSION`:

```bash
bash scripts/release/create_release_bundle.sh
```

Create a bundle in a specific output directory:

```bash
bash scripts/release/create_release_bundle.sh --output-dir dist
```

Create a bundle with an explicit version and replace an existing local output:

```bash
bash scripts/release/create_release_bundle.sh --version 1.2.0-beta.1 --output-dir dist --force
```

## Generated Files

Each run creates:

- `secureinfra-release-<version>/` with the selected public release files
- `secureinfra-release-<version>.zip`
- `secureinfra-release-<version>/SHA256SUMS.txt`
- `secureinfra-release-<version>/RELEASE-MANIFEST.json`

`SHA256SUMS.txt` uses standard `sha256sum`-style lines:

```text
<sha256>  <relative/path>
```

`RELEASE-MANIFEST.json` records the release name, version, generation time in
UTC, file count, and each bundled file's relative path, size in bytes, and
SHA256 hash.

## Verification

After extracting the release directory, verify checksums on Linux or macOS:

```bash
cd secureinfra-release-1.2.0-beta.1
sha256sum -c SHA256SUMS.txt
```

On macOS systems without `sha256sum`, use `shasum`:

```bash
cd secureinfra-release-1.2.0-beta.1
shasum -a 256 -c SHA256SUMS.txt
```

On Windows PowerShell, compare a manifest entry with `Get-FileHash`:

```powershell
$manifest = Get-Content .\secureinfra-release-1.2.0-beta.1\RELEASE-MANIFEST.json -Raw | ConvertFrom-Json
$readme = $manifest.files | Where-Object { $_.path -eq "README.md" }
(Get-FileHash .\secureinfra-release-1.2.0-beta.1\README.md -Algorithm SHA256).Hash.ToLowerInvariant() -eq $readme.sha256
```

## Optional Signing Hook

Signing is optional and intentionally not implemented by the release scripts.
Do not store signing keys, private certificates, tokens, or signing service
credentials in this repository.

If a release operator wants signed artifacts, signing should happen outside the
repository using keys managed by that operator. For example, after creating the
zip file, an operator-controlled environment could run a detached-signature
command such as:

```bash
gpg --detach-sign --armor dist/secureinfra-release-1.2.0-beta.1.zip
```

This example is documentation only. The repository does not provide, require,
or assume any signing key or paid signing service.
