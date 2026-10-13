# Cargo runner that makes doctests load the pinned SymCrypt on Windows. Usage, with SYMCRYPT_DLL set
# to the symcrypt.dll to load (.github/actions/setup-symcrypt sets it):
#
#   $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUNNER = "pwsh -NoProfile -File $PWD\ci\symcrypt-doctest-runner.ps1"
#   cargo test -p russh --no-default-features --features symcrypt --doc
#
# (Cargo splits the variable at spaces, so the script's path must not contain any.)
#
# rustdoc builds each doctest executable in a new temporary directory, where Windows would load
# C:\Windows\System32\symcrypt.dll: it searches the executable's directory and System32 before PATH.
# Since Rust 1.89, Cargo passes the target's runner to rustdoc (`--test-runtool`), which then runs
# `<runner> <executable>`. This script copies $env:SYMCRYPT_DLL next to the executable and runs it.
$ErrorActionPreference = 'Stop'

if ($args.Count -lt 1) { throw 'usage: symcrypt-doctest-runner.ps1 <executable> [arguments...]' }
if (-not $env:SYMCRYPT_DLL -or -not (Test-Path -LiteralPath $env:SYMCRYPT_DLL -PathType Leaf)) {
  throw "SYMCRYPT_DLL is '$env:SYMCRYPT_DLL', not a file; set it to the symcrypt.dll to load (.github/actions/setup-symcrypt does)"
}

$exe = [System.IO.Path]::GetFullPath($args[0])
$rest = @($args | Select-Object -Skip 1)
Copy-Item -LiteralPath $env:SYMCRYPT_DLL -Destination (Join-Path (Split-Path -Parent $exe) 'symcrypt.dll') -Force
& $exe @rest
exit $LASTEXITCODE
