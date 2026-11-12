# Installer engine (milestone M1.5)

The engine installs the running live system onto a blank disk: GPT, LUKS2 with argon2id, a recovery key, BIOS and UEFI
boot. The design, its decisions and its safety rules are [INSTALLER_DESIGN](../architecture/INSTALLER_DESIGN.md) (the
contract this page implements; the risk is R17 and the threat T10, the unencrypted `/boot`). This page is how to run it,
the plan and event reference, what each safety rule does in code, how it is tested, and what is **not** verified yet.

| Part | Where |
|---|---|
| The engine, `python3 -m installer` (standard library only, imports nothing from `backend/` or `kiosk/`) | [`installer/`](../../installer/README.md) |
| Unit tests on a fake machine | `installer/tests/` |
| Real-tools test in a privileged container | `installer/tests/integration/` |
| Installation of the package on the image (`/opt/pai/installer`), the unattended unit, the QEMU install test | image integration, not part of this milestone's code |

## Running it

```
python3 -m installer --plan /path/to/plan.json              # as root, on the live image
printf '%s' "$PASSPHRASE" | python3 -m installer --plan plan.json     # with "passphrase_source": "stdin"
```

* Root only (exit 77 otherwise). Progress is one JSON object per line on **stdout**; the log goes to **stderr**.
* With `"passphrase_source": "stdin"` the passphrase is all of standard input minus **one** trailing newline (`\n` or
  `\r\n`), at most 514 characters are read. With `"plan"` it is read from the plan file, which then holds a secret: that
  mode is for unattended provisioning only, and the file's permissions are the caller's responsibility.
* Exit status: **0** only when every step finished and the result was verified; **1** a step failed or a safety rule
  refused the target (everything acquired was released); **77** not root; **78** invalid plan.
* A refused plan or target touches nothing: no command runs, no recovery key file is written.

## Plan reference

Strict: unknown keys at any level, duplicate keys, wrong types and out-of-range values are errors, all reported together.
Messages name the field and the rule, never the value (a rejected passphrase is not echoed, nor is a JSON syntax error's text).

| Key | Required | Rule |
|---|---|---|
| `version` | yes | the integer `1` |
| `target` | yes | an object with **exactly one** of `by_id` (one name under `/dev/disk/by-id`, no slash, no leading dot) or `path` (a normalised absolute path under `/dev`) |
| `confirm_wipe` | yes | the JSON literal `true`; anything else (`"true"`, `1`, `false`, null) is refused |
| `hostname` | yes | one RFC 1123 label: 1 to 63 lowercase letters, digits, hyphens, not starting or ending with `-` |
| `username` | yes | `[a-z][a-z0-9_-]{0,31}`, not `root` |
| `passphrase_source` | yes | `"stdin"` or `"plan"` |
| `passphrase` | with `plan` only | 12 to 512 characters, not one character repeated, no control characters; **forbidden** with `stdin` |
| `recovery_key_file` | yes | a normalised absolute file path, not under `/dev`, `/proc`, `/sys`; must not exist yet |
| `kdf` | no | `{"memory_kib": null or 32..4194304, "iter_time_ms": null or 1..600000}`; `null` or absent leaves cryptsetup's benchmarked default; `luksDump` must still show argon2id |
| `extra_kernel_args` | no | default `""`; printable ASCII words, at most 256 characters and 32 words, none of `" ' \ ` $` |
| `after` | no | `"poweroff"`, `"reboot"` or `"none"` (default `"none"`) |

## Events

```json
{"event":"step","name":"luks-format","state":"start","detail":""}
{"event":"step","name":"luks-format","state":"done","detail":"LUKS2 container created on /dev/sda4"}
{"event":"step","name":"mount","state":"failed","detail":"mount failed (exit 32): ..."}
{"event":"step","name":"rollback","state":"done","detail":"everything released"}
{"event":"result","ok":false,"error":"step mount failed: mount failed (exit 32): ..."}
```

Steps, in order: `resolve-target`, `find-source`, `prepare-recovery-key` (these three change nothing), `wipe`, `partition`,
`verify-layout`, `luks-format`, `luks-recovery-key`, `luks-verify`, `luks-open`, `mkfs`, `identify-filesystems`, `mount`,
`copy-system`, `configure-files`, `chroot-mounts`, `remove-live-session`, `accounts`, `machine-id`, `initramfs`,
`bootloader`, `verify-installation`, `close`, `after`. After a failure a `rollback` step is reported (`done`, or `failed`
with what could not be released) and then the `result` event. Every text is redacted before it is written and cut at
2000 characters. The `after` action is queued with `systemctl --no-block`, so the result event is written before the
machine goes down.

## Safety rules, as implemented

| Rule of the design | In code | Test |
|---|---|---|
| 1. Whole block device, never a partition or a mapper device | `target.resolve_target`: the path must resolve to a node directly under `/dev` that is a block device; `/sys/block/<name>` must exist (partitions are not listed there); `dm-*`, `dm/` and `md/` devices are refused; read-only disks are refused | `test_target.py`, 23 refusal scenarios, each also run through the engine |
| 2. Not the live medium, nothing mounted, no swap, no mapping | The disk's device numbers, its partitions' and everything stacked on them (`holders/`, recursively) are compared with `/proc/self/mountinfo` and `/proc/swaps`. The live medium is *discovered*: any mount under `/run/live` or `/lib/live/mount` backed by the disk's tree is `live-medium`; no device name is known to the code | same file, including a medium on `nvme0n1p3` and one with no partition table |
| 3. `confirm_wipe` true, target named explicitly | `plan.py`; `TargetSpec` has no "auto" form; an empty target is `not-found` | `test_plan.py`, `test_target.py` |
| 4. At least 16 GiB | `MIN_TARGET_BYTES`, read from `/sys/block/<name>/size` | boundary tests at 16 GiB and one sector less |
| 5. Verify before copying | `verify_layout` (`sfdisk --json` against the design: GPT, 4 partitions, types, sizes, 1 MiB alignment, the rest for LUKS) and `verify_luks` (`luksDump --dump-json-metadata`: LUKS2, exactly 2 keyslots, all argon2id) run before the volume is opened; `verify-installation` (every `/etc/shadow` entry locked, the user exists and is in no administrative group, no live remnants, the boot loaders present) runs before closing | `test_steps_*.py`, `test_engine.py` |
| 6. Passphrase on stdin only; recovery key | `--key-file=-`, exact bytes, no newline (cryptsetup does not strip one for `-`); the recovery key is 256 random bits, base32 in groups of four, written 0600 with `O_EXCL` **before anything is destroyed** and added with `luksAddKey <device> <file>`: only the path is in argv | `test_engine.py::assert_no_leaks` over every call of every scenario; the integration test opens the container with both |
| 7. Rollback | the `ResourceStack`: every mount and the mapping register their undo *before* the command, so a timeout or interrupt mid-command is covered; undo runs newest first, continues past a failed release, and a failed release stays registered and is retried | one failure injected into every step and sub-command; timeouts after each acquisition; a failure inside rollback |
| 8. One runner, no shell | `runner.Commander`: list argv only, validated; timeout on every call (a test scans the source for it); the environment is built from scratch (`PATH`, `LC_ALL`, `LANG` plus a whitelist of one: `DEBIAN_FRONTEND`) | `test_runner.py`, `test_package.py` |

A completed installation keeps its `recovery_key_file`; one that fails (including by rollback) removes it, because it
opens nothing. If the run fails *after* the volume is closed (only the `after` action is left) the key is kept.

## What the engine does on the target

Layout and filesystems exactly as the design (partition names `bios-boot`, `esp`, `boot`, `cryptroot`; labels `PAI-ESP`,
`pai-boot`, `pai-root`). The mapping is named `cryptroot` during the installation and in `crypttab`, so `grub-probe` in the
chroot and the installed initramfs agree on the name.

* **Copy source.** The squashfs layer(s) live-boot mounted, *discovered* from the mount table (`squashfs` mounts under
  `/run/live/` or `/lib/live/mount/`), never the live overlay, with `rsync --archive --hard-links --acls --xattrs
  --numeric-ids --one-file-system`, excluding the contents (not the directories) of `/proc /sys /dev /run /tmp /mnt
  /media`, `/lost+found`, and `/boot/efi` (a FAT filesystem cannot take the owners and modes). Several layers are copied
  base first, in mount order.
* **Written files** (through `install -D -m ... /dev/stdin`): `/etc/fstab` and `/etc/crypttab` by UUID (no `discard`, no
  keyfile: `none`), `/etc/hostname`, `/etc/hosts`, and a GRUB drop-in `/etc/default/grub.d/90-pai-installer.cfg`
  (`GRUB_CMDLINE_LINUX` from `extra_kernel_args`, `GRUB_TIMEOUT=2`, `GRUB_DISABLE_OS_PROBER=true`), so the
  distribution's `/etc/default/grub` is not edited.
* **In the chroot** (bind mounts of `/dev`, `/sys`, `/run`, `proc`, each `--make-rslave` so unmounting cannot reach the
  live system; always released): the live user is deleted (name read from live-config's configuration, default `user`);
  installed `live-boot*`, `live-config*`, `live-tools` packages are purged (only those `dpkg-query` reports installed,
  including `config-files`); `/etc/live`, `/lib/live/config`, `/lib/live/boot`, `/var/lib/live`, `/etc/sudoers.d/live`
  and getty drop-ins that contain `autologin` are removed; root is locked; the primary user is created with a locked
  password and no group but its own; `/etc/machine-id` is emptied; `update-initramfs -u -k all`; `grub-install` for
  `i386-pc` (to the disk) and `x86_64-efi --removable --no-nvram`; `update-grub`.

## Testing

```
./.venv/Scripts/python.exe -m pytest -q installer          # unit tests, no root, any OS (3 tests are POSIX-only)
./.venv/Scripts/ruff.exe check installer && ./.venv/Scripts/ruff.exe format --check installer
bash installer/tests/integration/run.sh                    # real tools in a privileged container (Docker, network)
```

The unit tests run the whole engine on `installer/tests/fakes.py`, one object that is both the `Runner` and the `Host`. It
keeps enough state to behave like the tools where the installer depends on it (an `sfdisk` table that is read back, LUKS
keyslots that check the exact stdin bytes, mappings that cannot close while mounted, a mount table that `mount` and
`umount` change) and **fails the test on any command it does not know**. Every scenario ends with the same assertion
(`assert_no_leaks`): the passphrase and the recovery key, in either spelling, are in no argv, no environment value, no event,
no log line and no error text, and the passphrase is on the standard input of exactly the three `cryptsetup` commands that
need it.

### Integration test (`installer/tests/integration/run.sh`)

A privileged `debian:trixie-slim` container named `pai-inst-<timestamp>-<pid>` (removed when the run ends) installs
`cryptsetup`, `fdisk` (sfdisk), `dosfstools`, `e2fsprogs`, `rsync`, `acl`, `attr` and `util-linux`, makes a sparse 20 GiB
file, attaches it with `losetup --partscan`, and runs the engine's real step functions with the real runner against it
(`real_tools_check.py`): target resolution against the real `/sys`, recovery key file, wipe, partition, layout
verification, `luksFormat` with argon2id (small KDF values), recovery keyslot, verification, open, `mkfs`, UUID probing, the
three mounts, the real copy of a synthetic tree (hard link, symlink, setuid mode, numeric owner, xattr, ACL, excluded runtime
directories), a file written with `install -D /dev/stdin`, and the orderly close. The result is judged with the tools
themselves: `sfdisk --json` (GPT, four partitions, sizes 1 MiB / 512 MiB / 1 GiB / the rest, the four type GUIDs, 1 MiB
alignment), `cryptsetup luksDump` (version 2, two keyslots, both argon2id), `cryptsetup open --test-passphrase` (the
passphrase, the recovery key file and the recovery key as typed text open it; a wrong and a truncated passphrase do not),
`blkid` labels, `mountinfo`, `cryptsetup status` (nothing mapped), and a reopen with the recovery key alone that reads the
copied data back. The loop device must detach at the end.

The container has no udev, so a helper thread creates the partition and mapper nodes from `/sys`; the installer's wait for the
nodes (`verify_layout`) is exercised against it.

### Mutation check

The safety, secret and rollback tests were proved able to fail by breaking the code in a scratch copy, one change at a time,
and running the suite (stop at the first failure). 101 mutations: the target rules (partition, mapper, RAID, read-only, live
medium and each live-boot mount root, mounted, swap, active and nested mappings, size and its boundary, fail-closed on an
unreadable or malformed table), the plan rules, secret handling (passphrase or recovery key in argv, stdin of another command,
inherited environment, redaction removed or not registered, the key file's mode, exclusivity and directory), rollback (not run,
oldest first, a failed release stopping the rest or not retried, an undo registered after its command, the recovery key kept or
wrongly removed), step order, verification steps, accounts, `discard`/keyfile, copy flags. 100 were caught; 2 of those only on
Linux, because the tests of a real file's mode and exclusivity are POSIX-only (a 102nd, the key file's parent directory mode, was
added afterwards and is also caught on Linux only). The one survivor is equivalent: registering the ESP's unmount after its `mount` changes nothing, because the unmount of the root
filesystem it sits under is recursive and releases it anyway.

## What is and is not verified

Verified: the unit tests above (386 pass, 3 POSIX-only skipped on Windows; 389 pass on Debian 13's Python 3.13 as a non-root
user); the real-tools run above on cryptsetup 2.7.5, util-linux 2.41.5 and rsync 3.5.0 in `debian:trixie-slim`.

**Not verified, by design: the chroot, initramfs and GRUB steps** (`configure.mount_chroot_binds`, `remove_live_session`,
`create_accounts`, `reset_machine_id`, `boot.build_initramfs`, `boot.install_bootloader`, and `verify-installation` on a real
tree). They need a real installed system (kernel, the target's GRUB and cryptsetup packages, `dpkg`, device nodes) and are
covered here only by exact-argv tests on the fake. They are verified by the QEMU install test: boot the ISO, install, boot the
disk (BIOS; UEFI where OVMF is available), unlock, run the self-check on the installed system, and confirm a wrong passphrase
does not boot. Specific things that test must confirm: that `update-initramfs -u -k all` finds an initramfs for every kernel
(it uses `-u`, which needs an existing one), that `grub-probe` in the chroot names the root as `/dev/mapper/cryptroot`, that
`userdel` and `apt-get purge` succeed offline, and that the image carries what the engine needs.

### What the image must provide

`cryptsetup` and `cryptsetup-initramfs`, `fdisk` (for `sfdisk`), `dosfstools`, `e2fsprogs`, `rsync`, `util-linux`
(`blkid`, `mount`), `grub-pc-bin`, `grub-efi-amd64-bin`, `grub-common`, `initramfs-tools`, `passwd`, `dpkg`/`apt`, and the
`live-boot` layout (`/run/live/medium`, squashfs under `/run/live/rootfs/`). A missing tool fails the step that needs it (exit
127 is reported as `command not found`) and rolls back.

## Known limits

* A failed run leaves the target disk partly formatted (it was being destroyed); only the *session's* resources (mounts,
  mapping, the recovery key file) are released. Re-running with the same plan starts over.
* A plan with `"passphrase_source": "plan"` leaves the passphrase in a file the installer neither wipes nor protects.
* Nothing checks that `username` is free in the copied system before the copy; `useradd` fails the step later and the run
  rolls back.
* The recovery key is shown through its file only; wiping `/run/pai-install` (a tmpfs) is the caller's job after it was shown.
* The log (stderr) records every command's argv, which never holds a secret by construction; command output is not logged
  except in failure messages (redacted, last 800 characters).
