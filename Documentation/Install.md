## Installation

### From release zip/tarball
Windows:

- Download [latest
  release](https://github.com/dilluti0n/dpibreak/releases/latest) and
  unzip it.
- Double-click `dpibreak.exe` (or `start_fake.bat` to use
  [fake](#fake)).
- Run `service_install.bat` as administrator to automatically run per
  boot (Run `service_remove.bat` to remove).
- See `WINDOWS_GUIDE.txt` for more information (includes a Korean
  translation).

Linux:

Download latest release tarball from
[here](https://github.com/dilluti0n/dpibreak/releases/latest).

```bash
tar -xf DPIBreak-X.Y.Z-x86_64-unknown-linux-musl.tar.gz
cd DPIBreak-X.Y.Z-x86_64-unknown-linux-musl
sudo make install
```
To uninstall:

```bash
curl -fsSL https://raw.githubusercontent.com/dilluti0n/dpibreak/master/install.sh | sh -s -- uninstall

# Or if you have extracted tarball:
sudo make uninstall
```

### Windows (winget)
```powershell
winget install dpibreak
```

### Arch Linux
Available in the AUR as
[`dpibreak`](https://aur.archlinux.org/packages/dpibreak) (stable) and
[`dpibreak-git`](https://aur.archlinux.org/packages/dpibreak-git) (latest commit).

#### Using an AUR helper (e.g., [yay](https://github.com/Jguer/yay))
If `yay` is not installed, set it up first:
```bash
sudo pacman -S --needed base-devel git
git clone https://aur.archlinux.org/yay.git
cd yay && makepkg -si
```
Then install `dpibreak`:
```bash
yay -S dpibreak
```
#### Manual
```bash
git clone https://aur.archlinux.org/dpibreak.git && cd dpibreak && makepkg -si
```

### Gentoo Linux
Available in the [GURU](https://wiki.gentoo.org/wiki/Project:GURU)
repository.

```bash
sudo eselect repository enable guru
sudo emaint sync -r guru
echo 'net-misc/dpibreak ~amd64' | sudo tee -a /etc/portage/package.accept_keywords/dpibreak
sudo emerge --ask net-misc/dpibreak
```

### crates.io
Requirements: `libnetfilter_queue` development files
(e.g.,`libnetfilter-queue-dev` on Ubuntu/Debian).

```bash
cargo install dpibreak
```
Note: cargo installs to user directory, so sudo might not see
it. Use full path or link it:
```bash
# Option 1: Run with full path
sudo ~/.cargo/bin/dpibreak

# Option 2: Symlink to system bin (Recommended)
sudo ln -s ~/.cargo/bin/dpibreak /usr/local/bin/dpibreak
sudo dpibreak
```
