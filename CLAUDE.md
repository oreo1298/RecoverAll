# RecoverAll — repository notes for Claude

Data recovery for Linux (R-Studio / GetDataBack / TestDisk / PhotoRec): the `recoverctl` CLI, a root helper
started through pkexec, and a PySide6 app. Python ≥ 3.10. Primary target Arch Linux; `packaging/install.sh`
covers the other distributions. Design notes: docs/HOW-IT-WORKS.md.

## Layout
- `recoverall/core/` — stdlib only, no Qt imports:
  - `blockio.py`: `Source` (read-only byte range; `read()` zero-fills and records unreadable sectors in
    `src.bad`), `FileSource`, `BytesSource`, `RegionSource`, `ConcatSource` (free space as one source,
    `map_range`), `CachedSource`, `SplitSource`; `open_source(spec)` for paths, regions and `.rallraid`.
  - `vdisk.py`: native VHD/VHDX/VDI/VMDK/QCOW2/E01 readers (`open_vdisk`, tried by `open_source` on regular
    files); `check_raw_file` refuses repairs, table writes and loop devices on them (sectors aren't in order).
  - `fs/`: one reader per filesystem (`ntfs.py`, `fat.py`, `exfat.py`, `ext.py`, `xfs.py`, `hfsplus.py`,
    `iso9660.py`, `btrfs.py` via btrfs-progs, `tsk.py` via The Sleuth Kit). Contract in `fs/base.py`:
    `FsReader.probe(src)`, `entries(deleted=True, ctl)` yields `Entry` (key/parent/runs/data/chance/flags/extra),
    `free_extents()`; `Detector` (feed/finish) for things found during the single-pass deep scan
    (`ntfs.MftDetector`, `partsearch.BootSectorDetector`). Decoders (`extra["decoder"]`) for compressed content.
  - `carve/`: the signature search. `base.py` (`Format`, `Hit`, `Reader`), `engine.py` (`Carver`: strided magic
    search, `skip_inside`), one module per family (`images`, `video`, `audio`, `documents`, `archives`, `misc`,
    `misc2`), collected in `carve/__init__.py` (`FORMATS`, `resolve_formats`). Parsers find the real end of a file.
  - `fsdetect.py` (what is at an offset), `partitions.py` (read GPT/MBR/EBR/APM, `plan_table` → sfdisk script,
    `write_table`, `undo`), `partsearch.py` (quick/deep search, `merge_candidates`, `propose_table`),
    `bootrepair.py` (diagnose + fixes), `rawwrite.py` (busy checks, backups `.rallbak`, `write_at`, `restore`),
    `fsck.py` (fsck tools as actions), `filerepair.py`.
  - `scan.py` (`Scanner`: quick/deep/carve/photos presets, `run_scan`, `source_of`), `results.py` (`ScanDB`:
    SQLite `.rascan` files, volumes/entries/meta, key→parent, Lost files, filters, paging),
    `recover.py`, `preview.py`, `imaging.py` (ddrescue or builtin, ddrescue-format mapfiles), `raid.py`
    (`RaidSource`, md superblocks, `detect`), `devices.py`, `safety.py`, `tools.py`, `jobs.py`, `api.py`
    (`LocalAPI`, `RemoteAPI`, `wait_job`), `ipc.py`, `helper.py`, `session.py`, `demo.py` (`DemoAPI`).
- `recoverall/gui/` — PySide6. `bridge.py` (calls on worker threads, events → signals, `ensure_access`),
  `main_window.py`, pages `drives_page.py`, `recover_page.py` (+ `results_view.py`, `cellmap.py`),
  `photos_page.py`, `partitions_page.py`, `repair_page.py`, `imaging_page.py`, `history_page.py`; `dialogs.py`,
  `hexview.py`, `diskmap.py`, `jobview.py`, `common.py`, shared design system `theme.py`/`icons.py`/`widgets.py`.
- `recoverall/cli.py` — `recoverctl`. `tools/screenshot.py` — docs/screenshots from demo mode.

## Invariants / gotchas
- **Never write to the source.** Sources are opened `O_RDONLY` and never mounted. The only writes to disks are
  `partitions.write_table`, `bootrepair.*` and fsck actions, and every one goes through `rawwrite`
  (`check_not_busy`, `backup_ranges` first, `write_at` with read-back, `note_written`) so Undo works.
- Recovery destinations: `safety.check_destination` refuses any folder on the disk being recovered (also behind
  LVM and md). Root writes into a user's folder → files chowned to the caller (PKEXEC_UID/SUDO_UID).
- Offsets and sizes are bytes everywhere; `Entry.runs` are byte offsets in the *volume* (-1 = hole).
- Readers must never raise on garbage: damaged structures become fewer entries, `chance` POOR, or warnings.
  Deleted entries get `chance` from the allocation bitmap (GOOD = all clusters still free).
- Deep scans read the disk once: detectors and the carver are fed the same chunks. Carved files that a filesystem
  also lists (same `start`) are dropped (`ScanDB.drop_duplicates`).
- `.rascan` files are the results (SQLite). Entry ids are stable; the GUI pages them (`children`, `search`).
- Every destructive start goes through `safety.check_unmounted` + `check_confirmation` (typed serial). Keep both,
  also in `DemoAPI`.
- The helper serves one client over stdio; when stdin closes it cancels jobs and detaches loop devices.
- Demo mode: `DemoAPI` builds scans from canned scenarios; jobs run on a virtual clock (`RALL_DEMO_PACE`, tests
  use 0.02). Env for tests: `RALL_STATE_DIR`, `RALL_CONFIG_DIR`, `RALL_NO_HELPER`.

## Running
```sh
python -m venv --system-site-packages .venv && . .venv/bin/activate
pip install -e ".[dev]"
make test            # QT_QPA_PLATFORM=offscreen pytest; filesystem images are built with mkfs/mtools (missing → skip)
make test-root       # sudo: also loop devices and kernel mounts
make lint            # ruff
./recoverall.sh --demo
recoverctl --demo photos mmcblk0 /tmp/out
```
