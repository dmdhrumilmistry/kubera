# Kubera installer for Windows (PowerShell 5.1 or 7+):
#   irm https://raw.githubusercontent.com/dmdhrumilmistry/kubera/main/install.ps1 | iex
#
# Downloads the prebuilt binary for this CPU (x86_64 or ARM64) from the
# latest GitHub release, verifies its SHA-256 checksum, installs kubera.exe
# to a per-user directory and adds that directory to the user PATH.
#
# Environment:
#   KUBERA_VERSION         release tag to install (default: latest), e.g. v0.2.0
#   KUBERA_INSTALL_DIR     install directory (default: %LOCALAPPDATA%\Programs\kubera\bin)
#   KUBERA_DOWNLOAD_BASE   override the release download URL (https only; mirrors)
#   KUBERA_NO_MODIFY_PATH  set to 1 to leave the user PATH alone
#   KUBERA_VERIFY_ATTESTATION  set to 1 to also verify the GitHub build
#                          provenance attestation with `gh attestation verify`
#                          (needs the GitHub CLI, logged in)

& {
    Set-StrictMode -Version 2
    $ErrorActionPreference = 'Stop'
    # Invoke-WebRequest is many times slower with its progress bar.
    $ProgressPreference = 'SilentlyContinue'

    $Repo = 'dmdhrumilmistry/kubera'

    function Say([string]$Message) { [Console]::Error.WriteLine("kubera-install: $Message") }
    function Die([string]$Message) { Say "error: $Message"; throw "kubera-install: $Message" }

    # Windows PowerShell 5.1 may default to TLS 1.0; GitHub needs 1.2+.
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    function Get-Target {
        $arch = $null
        try {
            $arch = [string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
        } catch {
            # .NET Framework before 4.7.1: fall back to the environment. A
            # 32-bit PowerShell on a 64-bit OS reports the OS CPU here.
            $arch = $env:PROCESSOR_ARCHITEW6432
            if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
        }
        switch -Regex ($arch) {
            '^(X64|AMD64)$' { return 'x86_64-pc-windows-msvc' }
            '^(Arm64|ARM64)$' { return 'aarch64-pc-windows-msvc' }
            default { return $null }
        }
    }

    function Get-File([string]$Url, [string]$OutFile) {
        if (-not $Url.StartsWith('https://')) { Die "refusing to download over a non-https URL: $Url" }
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $OutFile
    }

    $target = Get-Target
    if (-not $target) {
        Say "no prebuilt binary for this CPU ($env:PROCESSOR_ARCHITECTURE)."
        Say 'install from source instead:  cargo install kubera-cli --locked'
        return
    }

    $version = if ($env:KUBERA_VERSION) { $env:KUBERA_VERSION } else { 'latest' }
    if ($env:KUBERA_DOWNLOAD_BASE) {
        $base = $env:KUBERA_DOWNLOAD_BASE.TrimEnd('/')
    } elseif ($version -eq 'latest') {
        $base = "https://github.com/$Repo/releases/latest/download"
    } else {
        $base = "https://github.com/$Repo/releases/download/$version"
    }

    $dir = if ($env:KUBERA_INSTALL_DIR) {
        $env:KUBERA_INSTALL_DIR
    } else {
        Join-Path $env:LOCALAPPDATA 'Programs\kubera\bin'
    }

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("kubera-install-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $asset = "kubera-$target.zip"
        $archive = Join-Path $tmp $asset
        Say "downloading $asset ($version)"
        try {
            Get-File "$base/$asset" $archive
        } catch {
            Say "download failed: $($_.Exception.Message)"
            Say 'If no release exists yet, install from source:  cargo install kubera-cli --locked'
            throw
        }
        try {
            Get-File "$base/$asset.sha256" "$archive.sha256"
        } catch {
            Die "checksum download failed: $($_.Exception.Message)"
        }

        $line = (Get-Content -LiteralPath "$archive.sha256" -TotalCount 1)
        $expected = if ($line) { ($line.Trim() -split '\s+')[0].ToLowerInvariant() } else { '' }
        $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($expected -notmatch '^[0-9a-f]{64}$' -or $expected -ne $actual) {
            Die "checksum mismatch for $asset (expected $expected, got $actual)"
        }

        if ($env:KUBERA_VERIFY_ATTESTATION -eq '1') {
            if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
                Die 'KUBERA_VERIFY_ATTESTATION=1 needs the GitHub CLI (gh) on PATH'
            }
            Say 'verifying build provenance attestation'
            & gh attestation verify $archive --repo $Repo --signer-workflow "$Repo/.github/workflows/release.yml" | Out-Null
            if ($LASTEXITCODE -ne 0) { Die "attestation verification failed for $asset" }
        }

        $unpacked = Join-Path $tmp 'unpacked'
        Expand-Archive -LiteralPath $archive -DestinationPath $unpacked
        $exe = Join-Path $unpacked 'kubera.exe'
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { Die "$asset does not contain kubera.exe" }

        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $dest = Join-Path $dir 'kubera.exe'
        $old = "$dest.old"
        $hadOld = Test-Path -LiteralPath $dest
        if ($hadOld) {
            # A running kubera.exe cannot be overwritten, but it can be renamed.
            Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
            Move-Item -LiteralPath $dest -Destination $old -Force
        }
        try {
            Copy-Item -LiteralPath $exe -Destination $dest
        } catch {
            if ($hadOld) { Move-Item -LiteralPath $old -Destination $dest -Force }
            throw
        }
        # Fails harmlessly while the old binary is still running.
        Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue

        $installed = try { (& $dest --version) 2>$null } catch { 'kubera' }
        Say "installed $installed to $dest"

        $onPath = ($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $dir.TrimEnd('\') }
        if ($env:KUBERA_NO_MODIFY_PATH -eq '1') {
            if (-not $onPath) { Say "note: $dir is not on your PATH" }
        } else {
            $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
            $entries = if ($userPath) { $userPath -split ';' | Where-Object { $_ } } else { @() }
            if (-not ($entries | Where-Object { $_.TrimEnd('\') -ieq $dir.TrimEnd('\') })) {
                [Environment]::SetEnvironmentVariable('Path', (@($entries) + $dir) -join ';', 'User')
                Say "added $dir to your user PATH (open a new terminal to use it)"
            }
            if (-not $onPath) { $env:Path = "$env:Path;$dir" }
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
