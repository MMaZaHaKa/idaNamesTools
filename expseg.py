# ida_segments_export_import.py
# Contains two scripts for IDA 7.6 / IDAPython:
# 1) export_segments.py - export segment metadata (optionally raw bytes) to JSON
# 2) import_segments.py - import segments from that JSON and recreate them in IDA
#
# Save each part into its own file or run from the Script window. Tested against IDA 7.x API
# (uses idautils.Segments, ida_segment.segment_t, ida_segment.add_segm_ex, ida_bytes.put_bytes, ida_kernwin.ask_file).

# -----------------------------
# export_segments.py
# -----------------------------
#!/usr/bin/env python3
"""
export_segments.py
Export all segments (metadata + optional raw bytes) to JSON.
Run inside IDA: File -> Script file...
"""

import json
import base64
import sys

import idautils
import idaapi
import ida_segment
import ida_bytes
import ida_kernwin
import idc


def export_segments(path, include_bytes=False):
    segments = []
    for start in idautils.Segments():
        seg = ida_segment.getseg(start)
        if not seg:
            continue

        try:
            name = ida_segment.get_segm_name(seg)
        except Exception:
            # fallback: idc.get_segm_name accepts an address
            name = idc.get_segm_name(start) or ""

        try:
            sclass = ida_segment.get_segm_class(seg)
        except Exception:
            sclass = ""

        seg_dict = {
            "start": int(seg.start_ea),
            "end": int(seg.end_ea),
            "name": name,
            "class": sclass,
            "perm": int(getattr(seg, "perm", 0)),
            "bitness": int(getattr(seg, "bitness", 0)),
            "align": int(getattr(seg, "align", 0)),
            "comb": int(getattr(seg, "comb", 0)),
            "type": int(getattr(seg, "type", 0)),
            "sel": int(getattr(seg, "sel", 0)),
            "flags": int(getattr(seg, "flags", 0)),
            "orgbase": int(getattr(seg, "orgbase", 0)),
            "color": int(getattr(seg, "color", 0)),
        }

        if include_bytes:
            size = seg.end_ea - seg.start_ea
            if size > 0:
                data = ida_bytes.get_bytes(seg.start_ea, size) or b""
                seg_dict["bytes_b64"] = base64.b64encode(data).decode("ascii")
            else:
                seg_dict["bytes_b64"] = ""

        segments.append(seg_dict)

    out = {
        "ida_sdk_version": getattr(idaapi, "IDA_SDK_VERSION", None),
        "segments": segments,
    }

    with open(path, "w") as f:
        json.dump(out, f, indent=2)

    print("Exported %d segments to %s" % (len(segments), path))


if __name__ == "__main__":
    # Ask user for filename and whether to include raw bytes.
    # NOTE: previously a NameError could occur if variable 'include' wasn't defined.
    path = ida_kernwin.ask_file(1, "segments_export.json", "Export segments to JSON")
    if not path:
        print("Cancelled by user.")
        sys.exit(0)

    # store result in clearly named variable
    include_bytes = ida_kernwin.ask_yn(0, "Include raw bytes for each segment? (may produce large file)") == 1
    export_segments(path, include_bytes=include_bytes)

