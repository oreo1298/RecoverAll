#!/usr/bin/env python3
"""Write recoverall/core/media/aac_tables.py from the VisualOn AAC encoder's constant tables.

The Huffman codebooks of AAC (ISO/IEC 14496-3, 4.A.1) and the scale factor band tables are data the encoder
needs as much as a decoder does; vo-aacenc (Apache License 2.0) has them in aacenc/src/aac_rom.c:

* huff_ctab1 .. huff_ctab11, huff_ctabscf: the codewords, indexed like the standard's tables (books 1-4 by
  27*w + 9*x + 3*y + z, books 5-11 by n*y + z, signed books offset by their largest absolute value; the
  scalefactor book by delta + 60);
* huff_ltab1_2, huff_ltab3_4, huff_ltab5_6, huff_ltab7_8, huff_ltab9_10: the codeword lengths of two books
  packed in one 16-bit number, the odd book in the high byte and the even book in the low byte (bit_cnt.c:
  HI_LTAB / LO_LTAB); huff_ltab11 and huff_ltabscf hold one book each;
* sfBandTabLong / sfBandTabShort with sfBandTabLongOffset / sfBandTabShortOffset and sfBandTotalLong /
  sfBandTotalShort: the band offsets of 1024- and 128-line windows per sampling-frequency index 0..11
  (96 kHz .. 8 kHz; 7350 Hz, index 12, uses the 8 kHz tables).

The script checks that every book is a complete prefix code before writing anything.

Usage: tools/gen_aac_tables.py path/to/vo-aacenc/aacenc/src/aac_rom.c [-o recoverall/core/media/aac_tables.py]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "recoverall" / "core" / "media" / "aac_tables.py"

HEADER = '''"""Huffman codebooks of ISO/IEC 14496-3, converted from the VisualOn AAC encoder (vo-aacenc), Copyright
2003-2010 VisualOn, Inc., Apache License 2.0; modified: converted to Python tables by tools/gen_aac_tables.py.

The scale factor band tables come from the same file (aacenc/src/aac_rom.c). See LICENSES/Apache-2.0.txt.
Generated: do not edit; run tools/gen_aac_tables.py instead.

SPECTRAL[book] = (lengths, codewords) for books 1-11, indexed like the standard's tables: books 1-4 by
27*w + 9*x + 3*y + z, books 5-11 by n*y + z, the signed books (1, 2, 5, 6) with every value offset by the
book's largest absolute value. SCALEFACTOR = (lengths, codewords) indexed by delta + 60.
SWB_LONG[i] / SWB_SHORT[i]: the scale factor band offsets of a 1024-line / 128-line window at sampling-frequency
index i (0 = 96 kHz .. 11 = 8 kHz, 12 = 7350 Hz), ending with the window length.
"""
'''

# book -> (length table, packed half: "hi", "lo" or None)
LENGTHS = {1: ("huff_ltab1_2", "hi"), 2: ("huff_ltab1_2", "lo"), 3: ("huff_ltab3_4", "hi"),
           4: ("huff_ltab3_4", "lo"), 5: ("huff_ltab5_6", "hi"), 6: ("huff_ltab5_6", "lo"),
           7: ("huff_ltab7_8", "hi"), 8: ("huff_ltab7_8", "lo"), 9: ("huff_ltab9_10", "hi"),
           10: ("huff_ltab9_10", "lo"), 11: ("huff_ltab11", None)}
SIZES = {1: 81, 2: 81, 3: 81, 4: 81, 5: 81, 6: 81, 7: 64, 8: 64, 9: 169, 10: 169, 11: 289}


def c_tables(text: str) -> dict[str, list[int]]:
    """Every `const <type> name[...] = { numbers };` of a C file, flattened (comments removed)."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    out: dict[str, list[int]] = {}
    for m in re.finditer(r"const\s+[\w\s]+?\b(\w+)\s*((?:\[[^\]]*\])+)\s*=\s*\{(.*?)\}\s*;", text, flags=re.S):
        name, body = m.group(1), m.group(3)
        out.setdefault(name, [int(v, 0) for v in re.findall(r"0[xX][0-9a-fA-F]+|\d+", body)])
    return out


def check_book(name: str, lengths: list[int], codes: list[int]) -> None:
    """Fail unless the codewords are a complete prefix code with the given lengths."""
    words = sorted(zip(lengths, codes))
    seen: set[tuple[int, int]] = set()
    for length, code in words:
        if not 0 < length <= 19 or code >> length:
            sys.exit(f"{name}: codeword {code:#x} does not fit in {length} bits")
        for k in range(1, length):
            if (k, code >> (length - k)) in seen:
                sys.exit(f"{name}: codeword {code:#x}/{length} has a shorter codeword as prefix")
        seen.add((length, code))
    kraft = sum(2.0 ** -length for length, _ in words)
    if abs(kraft - 1.0) > 1e-12:
        sys.exit(f"{name}: not a complete code (Kraft sum {kraft})")


def py_list(values, indent: int = 4, width: int = 118) -> str:
    """A tuple literal wrapped to WIDTH characters."""
    lines, line = [], " " * indent + "("
    for i, v in enumerate(values):
        item = f"{v}," if i + 1 < len(values) else f"{v})"
        if len(line) + len(item) + 1 > width:
            lines.append(line.rstrip())
            line = " " * (indent + 1)
        line += item + " "
    lines.append(line.rstrip())
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("aac_rom", type=Path, help="vo-aacenc's aacenc/src/aac_rom.c")
    ap.add_argument("-o", "--output", type=Path, default=OUT)
    args = ap.parse_args(argv)
    t = c_tables(args.aac_rom.read_text(encoding="latin-1"))

    books = {}
    for book, (lname, half) in LENGTHS.items():
        packed = t[lname]
        lengths = [v >> 8 if half == "hi" else v & 0xFF for v in packed] if half else packed
        codes = t[f"huff_ctab{book}"]
        if len(lengths) != SIZES[book] or len(codes) != SIZES[book]:
            sys.exit(f"book {book}: {len(lengths)} lengths, {len(codes)} codewords, expected {SIZES[book]}")
        check_book(f"book {book}", lengths, codes)
        books[book] = (lengths, codes)
    scf = (t["huff_ltabscf"], t["huff_ctabscf"])
    if len(scf[0]) != 121 or len(scf[1]) != 121:
        sys.exit("scalefactor book: expected 121 codewords")
    check_book("scalefactor book", *scf)

    rates = t["sampRateTab"]
    swb = {}
    for kind, frame in (("Long", 1024), ("Short", 128)):
        tab, offs, totals = t[f"sfBandTab{kind}"], t[f"sfBandTab{kind}Offset"], t[f"sfBandTotal{kind}"]
        rows = [tab[o:o + n + 1] for o, n in zip(offs, totals)]
        for rate, row in zip(rates, rows):
            if row[0] != 0 or row[-1] != frame or any(b <= a for a, b in zip(row, row[1:])):
                sys.exit(f"sfBandTab{kind} at {rate} Hz is not a list of band offsets 0..{frame}")
        swb[kind] = rows + [rows[-1]]          # index 12, 7350 Hz, uses the 8 kHz bands

    out = [HEADER, "SPECTRAL = {"]
    for book, (lengths, codes) in books.items():
        out.append(f"    {book}: (")
        out.append(py_list(lengths, 8) + ",")
        out.append(py_list(codes, 8) + "),")
    out.append("}")
    out.append("")
    out.append("SCALEFACTOR = (")
    out.append(py_list(scf[0]) + ",")
    out.append(py_list(scf[1]) + ")")
    out.append("")
    out.append(f"SAMPLE_RATES = {tuple(rates) + (7350,)}")
    for kind in ("Long", "Short"):
        out.append("")
        out.append(f"SWB_{kind.upper()} = (")
        for row in swb[kind]:
            out.append(py_list(row) + ",")
        out.append(")")
    args.output.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
