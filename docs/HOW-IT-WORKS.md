# How RecoverAll works

## Everything is a read-only byte range

The engines never open `/dev/sda2`. They read a **source** (`core/blockio.py`): a read-only byte range with
`read(offset, length)`. A disk, an image file, a partition (a region of a disk), the free space of a
volume (the free extents glued together), a split image (`.001`, `.002`…) and a virtual RAID are all
sources. Every reader, detector and parser works on them, so the same code recovers from a disk, from an
image of it, and from the test suite's images.

`read()` always returns the number of bytes asked for. A sector that can't be read (EIO on a failing
disk) is retried one sector at a time, then returned as zeros and recorded in `src.bad`. Recovery reports
every file that touches such a sector, and a scan never stops because of one. Disks are opened `O_RDONLY`
and never mounted. Nothing in a scan, a preview or a recovery writes to them.

## A scan (`core/scan.py`)

A scan runs these steps, then saves everything in a `.rascan` file:

1. **The partition table** (`partitions.read_table`): GPT (falling back to the backup copy when the main one
   is damaged), MBR with its chain of extended boot records, or Apple Partition Map. Without a table, the
   whole source is one volume (memory cards and USB sticks are often formatted that way).
2. **Deep scans read the whole disk once**, in 8 MiB chunks, and feed every chunk to every detector:
   `partsearch.BootSectorDetector` (boot sectors, superblocks and their backups of every filesystem),
   `ntfs.MftDetector` (MFT records, to rebuild NTFS volumes whose boot sectors are gone) and the signature
   search. Volumes found this way that the partition table doesn't list are added as *found* volumes.
3. **The filesystems**: each volume is opened with its reader, which lists every file and folder it can
   find, the deleted ones included. FAT is also searched for orphaned folders (after a quick format), and
   XFS for freed inode chunks, on deep scans.
4. **Signatures**: *Signatures only* and *Photos* scans search the free space of each volume (or the whole
   disk) for files by their content.
5. **Finish**: entries are linked to their folders. Entries whose folder is unknown, or that are part of a
   loop of folders, go to *Lost files*. A file found by signature that a filesystem also lists (same start)
   is dropped, and the counts are made.

The **scan map** in the app has one cell per 1/1600 of the disk: read, holding filesystem metadata, holding
a file found by signature (colored by type), or unreadable.

`.rascan` files are SQLite databases: `volumes` (filesystem, offset, size, label, origin: partition table,
found, or signature search), `entries` (name, parent, size, times, deleted, chance, flags, the byte runs of
the content or the content itself for small files, and reader-specific details) and `meta` (the source,
the options, the statistics). They can be opened again later, saved anywhere, and paged through without
loading them in memory. That is how the app browses millions of files.

## Finding deleted files

Each filesystem forgets deleted files differently, so each reader (`core/fs/`) looks in a different place:

| Filesystem | What a delete leaves behind | What RecoverAll uses |
|---|---|---|
| NTFS | the MFT record (name, folder, times, the list of clusters) with its in-use flag cleared | every MFT record; folders rebuilt from the parent references |
| FAT | the folder entry with its first byte replaced by 0xE5; the FAT chain zeroed | name, size and first cluster; the file is assumed contiguous (like every FAT undelete tool) |
| exFAT | the entry set with the "in use" bits cleared; the NoFatChain flag | exact runs for contiguous files, the FAT chain when it still matches |
| ext3/ext4 | an inode with its block map cleared, the folder entry wiped | the jbd2 journal's older copies of inode tables and folder blocks |
| XFS | the folder entry's name; the extent records in the freed inode | the inode's extents, the name from the folder |
| HFS+ | catalog records in node slack, freed nodes and the journal | every catalog record that parses and whose ID is free |
| Btrfs | older copies of the trees (copy-on-write) | older tree roots found by `btrfs-find-root` |

Each deleted file gets a **chance**: *good* when every cluster it used is still free in the allocation
bitmap, *poor* when some are now used by another file (its content was probably overwritten), *fair* when
it can't be told (a contiguity guess on FAT, a carved file whose end is a guess).

**Damaged filesystems.** When the NTFS boot sectors are gone, `MftDetector` finds MFT records anywhere on
the disk. Their record numbers and cluster runs give away the cluster size and where the volume started,
the way GetDataBack does. FAT folders survive a quick format, because every folder starts with `.` and
`..` entries, and they are searched for in the data area. ext, XFS, HFS+ and exFAT volumes with a damaged
main superblock or boot sector are opened from their backup copies.

## The signature search (`core/carve/`)

Like PhotoRec, it looks only at the start of each block (512 bytes, or the volume's cluster size), because
files start on block boundaries. Finding candidates doesn't loop over blocks in Python. For each magic, the
two rarest of its bytes are anchors. The chunk is sliced with a stride of one block at each anchor's offset
(`buf[k::block]`: one byte per block). Each slice is translated through a table that marks the bytes some
magic wants there, and the marks are ANDed as big integers. Only the blocks left get their whole magic
compared.

Then the format's parser reads the file's own structure to **find where it ends**. That means JPEG markers
and EXIF thumbnails, PNG chunks, MP4/MOV boxes, RIFF and Matroska sizes, ZIP central directories (and
whether a ZIP is really a DOCX, XLSX, ODT, EPUB or APK), PDF `%%EOF` with incremental updates, OLE sector
chains (DOC/XLS/PPT/MSG), SQLite page counts, the TIFF structure of RAW photos, MP3 frame chains, and more.
119 formats are known (`recoverctl formats`). The blocks inside a found file aren't searched again. A
format whose length can't be told ends where the next file starts, with at most a *fair* chance. Files
found this way have no names, so photos are named from their EXIF data (date and camera) where they can
be, and the others from where they were found.

## Lost partitions (`core/partsearch.py`, `core/partitions.py`)

**Quick Search** probes where partitions usually start: every 1 MiB, the 63-sector and cylinder
boundaries of old DOS layouts, and the partitions of the current and backup tables. It reads 68 KiB at
each probe. A filesystem whose size is known makes the search jump to its end. **Deep Search** reads every
sector once with `BootSectorDetector`. It finds main structures and their backups (NTFS backup boot
sector, FAT32 backup at sector 6, exFAT backup boot region, ext backup superblocks, XFS allocation-group
headers, Btrfs mirrors, the HFS+ alternate header…), and works out each volume's start from the backup's
own fields.

`merge_candidates` combines duplicates. A main structure confirmed by its backup is the strongest evidence,
and a size from a boot sector beats one estimated from metadata. Volumes inside other volumes (a disk image
stored as a file) are set aside. Overlaps are settled by picking the set of non-overlapping volumes with
the most total support (weighted interval scheduling), so one stale filesystem can't hide three real
partitions. `propose_table` turns the result into a GPT or MBR table (with logical partitions in an
extended one), and `plan_table` checks it and writes the `sfdisk` script.

**Writing** (`partitions.write_table`, `core/rawwrite.py`):

1. Refused if the disk or one of its partitions is mounted, used as swap, held by LVM, RAID or encryption,
   or (for image files) attached to a loop device that is.
2. Every byte range that may change (MBR, both GPT copies, the extended boot records) is saved into a
   `.rallbak` file in `/var/lib/recoverall/backups`. The file holds a JSON header (the disk's size, a hash
   of its first 4 KiB, serial and model, and each range with its SHA-256) and then the raw bytes.
3. `sfdisk` writes the table, the table is read back and compared with the plan, and the backup records
   what the disk looks like now.
4. **Undo** checks the backup's hashes and that it's the same disk, saves the current bytes (so the undo
   can be undone too), and writes the old ones back.

Boot-sector repairs (`core/bootrepair.py`) go through the same backup-write-verify path. They copy the
NTFS or FAT32 backup boot sector, or the exFAT backup boot region, over the damaged one, rebuild the main GPT from the backup or the reverse, and write a protective MBR or the 55 AA signature.
They also copy one FAT over the other. To decide which copy is right, each one gets a count of impossible
entries, links to clusters that the same copy calls free, and root-folder files whose first cluster it
calls free. A copy that lost its chains (zeroed by an interrupted write) shows up in the last two counts.

## Failing disks (`core/imaging.py`)

A failing disk gets worse with every read, so it should be read once, the easy parts first. With GNU
ddrescue installed, *Imaging* runs it with a mapfile: copy, then trim, scrape and retry the bad areas.
Without it, the built-in imager does the same in two passes. It reads in big blocks and skips ahead after
an error, then goes back to the skipped areas sector by sector. It writes a ddrescue-format mapfile, so
either tool can continue the other's work. The live map shows rescued, not yet tried and bad areas. Scan
the image afterwards: unreadable sectors are zeros, and files that touch them are marked.

## Virtual RAID (`core/raid.py`)

`RaidSource` reads RAID 0, 1, 10 (near copies), 5 (the four md layouts) and 6, and JBOD, from member disks
or images, with a data offset per member. RAID 5 and 6 rebuild a missing member's chunks from parity on the
fly. The parameters come from Linux md superblocks (0.90 and 1.x) when the members have them. Otherwise
`detect` tries every member order (including where the missing members were), chunk size and layout. When
every member is present, the members XORing to zero proves RAID 5 whatever the order.

Each candidate is scored on structures that only line up with the right geometry, because they lie far
apart in different chunks:

- the partition table and its backup GPT in the array's last sector;
- the two FAT copies agreeing, and FAT chains running cluster after cluster;
- ext backup superblocks at their block groups, and XFS allocation-group headers;
- NTFS MFT records numbered in order, and the backup boot sector at the volume's end;
- for the best candidates, files whose first bytes match their extension.

The best definition is saved as a `.rallraid` file (plain JSON) and scanned like a disk.

## Root, the helper and demo mode

Reading disks needs root, but the app runs as the user. When it needs a disk it starts
`recoverall-helper` through pkexec (polkit asks for the password once). The helper answers the same API
(`core/api.py`, `LocalAPI`) over a pipe, in JSON lines (`core/ipc.py`), and sends job progress as events.
The GUI and `recoverctl` talk to `LocalAPI` (as root) or `RemoteAPI` (through the helper) without knowing
which. Image files the user can read are opened without the helper.

Files recovered into a user's folder are given to that user (`PKEXEC_UID` / `SUDO_UID`), and names that
Windows can't store are made safe when the destination is FAT or NTFS. Recovering onto the disk being
recovered is refused (`core/safety.py`). The check follows partitions, LVM and md down to the physical
disks.

**Demo mode** (`--demo`) replaces the API with `DemoAPI`. It has six simulated disks: a Windows SSD, a disk
whose partition table was wiped, a failing disk, a camera card full of deleted photos, a quick-formatted USB
stick and a Linux system disk. Scans are generated from canned scenarios into real `.rascan` files, and jobs
run on a virtual clock. The screenshots in this folder come from it (`make screenshots`).
