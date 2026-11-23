# To produce release zip/tarball

Release builds and deployments are automated via GitHub Actions. See
[.github/workflows/release.yml](.github/workflows/release.yml) for
details. Compilation requires Rust toolchain. See
<https://www.rust-lang.org/learn/get-started>.

Windows: `.\build.ps1` (fetches WinDivert with
[scripts/fetch-windivert.ps1](scripts/fetch-windivert.ps1) if missing).

Linux:
```sh
rustup target add x86_64-unknown-linux-musl
make tarball
```
This builds a static musl binary, as the release does. To build against
glibc instead, set `BUILD_TARGET`:
```sh
make tarball BUILD_TARGET=x86_64-unknown-linux-gnu
```
The resulting binary needs the build host's glibc version or newer.

Release zip/tarball should be ready on directory `dist`.
