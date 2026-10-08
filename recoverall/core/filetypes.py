"""File categories by extension: what the type chips filter on and which icon a file gets."""

from __future__ import annotations

CATEGORY_NAMES = {
    "photo": "Photos",
    "video": "Videos",
    "audio": "Music",
    "document": "Documents",
    "archive": "Archives",
    "email": "E-mail",
    "database": "Databases",
    "executable": "Programs",
    "other": "Other",
}

_EXTS = {
    "photo": "jpg jpeg jpe jfif png gif bmp dib tif tiff webp heic heif avif psd psb ico cur svg svgz xcf exr jp2 j2k "
             "jxl tga dds raw cr2 cr3 crw nef nrw arw srf sr2 dng orf rw2 raf pef srw x3f kdc dcr mrw erf 3fr iiq mpo "
             "dcm dicom fits fit pcx emf wmf ai eps".split(),
    "video": "mp4 m4v mov qt 3gp 3g2 avi mkv webm wmv asf flv f4v mpg mpeg mpe vob ts mts m2ts m2t mxf rm rmvb ogv "
             "divx dv insv lrv".split(),
    "audio": "mp3 wav flac ogg oga opus m4a m4b m4r aac wma aiff aif aifc amr mid midi ape wv au snd caf dsf dff "
             "ra mka ac3 dts".split(),
    "document": "pdf doc docx docm dot dotx xls xlsx xlsm xlsb xlt ppt pptx pptm pps ppsx odt ods odp odg odf rtf "
                "txt text md csv tsv json xml html htm xhtml epub mobi azw azw3 djvu chm xps oxps ps wpd wps wri pages "
                "numbers key vsd vsdx pub one tex log ini cfg conf yaml yml".split(),
    "archive": "zip rar 7z gz tgz bz2 tbz2 xz txz zst lz4 lz lzma tar cab cpio arj lzh lha xar wim iso img dmg "
               "squashfs sqsh z".split(),
    "email": "pst ost mbox eml msg dbx mbx emlx".split(),
    "database": "sqlite sqlite3 db db3 mdb accdb kdbx kdb regf dbf sql frm ibd myd edb".split(),
    "executable": "exe dll sys efi msi elf so o ko bin apk jar aar ipa class dex deb rpm appimage dylib macho wasm "
                  "pyc".split(),
    "other": "ttf otf ttc woff woff2 swf torrent ics vcf lnk evtx blend pem crt cer key plist vmdk vdi vhd vhdx "
             "qcow2".split(),
}

EXT_CATEGORY: dict[str, str] = {}
for _cat, _exts in _EXTS.items():
    for _e in _exts:
        EXT_CATEGORY.setdefault(_e, _cat)


def extension(name: str) -> str:
    """The lowercase extension of NAME without the dot ("" if none; "tar.gz" → "gz")."""
    base = name.rsplit("/", 1)[-1]
    if base.startswith(".") and base.count(".") == 1:
        return ""
    stem, dot, ext = base.rpartition(".")
    if not dot or not stem or len(ext) > 10 or " " in ext:
        return ""
    return ext.lower()


def category(name: str, is_dir: bool = False) -> str:
    if is_dir:
        return ""
    return EXT_CATEGORY.get(extension(name), "other")
