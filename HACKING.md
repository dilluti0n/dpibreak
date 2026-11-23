# Hacking on DPIBreak

Patches are welcome.

## Building

Compilation requires Rust toolchain. See
<https://www.rust-lang.org/learn/get-started>.

Release builds and deployments are automated via GitHub Actions. See
[.github/workflows/release.yml](.github/workflows/release.yml) for
details. To produce the release zip/tarball locally:

Windows: `.\build.ps1` (fetches WinDivert with
[scripts/fetch-windivert.ps1](scripts/fetch-windivert.ps1) if missing).

Linux:

    rustup target add x86_64-unknown-linux-musl
    make tarball

This builds a static musl binary, as the release does. To build against
glibc instead, set `BUILD_TARGET`:

    make tarball BUILD_TARGET=x86_64-unknown-linux-gnu

The resulting binary needs the build host's glibc version or newer.

Release zip/tarball should be ready on directory `dist`.

## Sending patches

Open a pull request on [GitHub](https://github.com/dilluti0n/dpibreak).
Commits may be reworded or squashed when they are applied.

CI runs these:

    cargo fmt --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked

## Commit messages

Keep each commit to one logical change.

The subject is `area: summary`, with the summary in lowercase and the
imperative mood, without a trailing period:

    pkt: skip fake packet if resolved TTL is zero
    linux: also queue forwarded ClientHello on nftables
    docs: fix the tarball and directory names in Install.md

Use an area that `git log` already has: `pkt`, `opt`, `tls`, `log`,
`linux`, `windows`, `platform`, `build`, `ci`, `scripts`, `pkg`,
`docs`. Use plain `docs:`, not `docs: FILE:`. A change that fits no
area, such as editing `.gitignore`, gets no prefix and a capitalized
subject:

    Drop old root-level entries from .gitignore

The body says why the change is needed, if the subject does not make
that obvious. A sentence or two is often enough. Wrap it at 72
columns.

Add these trailers at the end of the message where they apply, one
per line:

- `Fixes: <12-char hash> ("<subject>")`: the commit that introduced
  the bug. Print it with
  `git log -1 --abbrev=12 --format='%h ("%s")' <commit>`.
- `Closes: <URL>`: the issue this commit resolves.
- `Link: <URL>`: anything else worth pointing at, including issues
  you don't want GitHub to close.

For example, a commit that only references an issue:

    scripts: add test for local server autottl

    Link: https://github.com/dilluti0n/dpibreak/issues/27

and the one that resolves it:

    pkt: skip fake packet if resolved TTL is zero

    Closes: https://github.com/dilluti0n/dpibreak/issues/27

## AI coding assistants

We encourage you to use them. Besides writing code, they make chores
that are tedious with the usual tools, such as benchmarking or tracking
down regressions, much easier.

Whatever tools you use, keep a change to what it needs. AI tools tend to
add extras along the way, and neither of us wants that.

Nobody cares how you wrote it, so do not add any attribution for the
tool to the commit. No `Co-Authored-By`, `Assisted-by` or "Generated
with" lines.
