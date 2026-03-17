# -----------------------------
# import_segments.py
# -----------------------------
#!/usr/bin/env python3
"""
import_segments.py
Import segments from JSON created by export_segments.py and recreate them in the IDB.
Options are provided to delete existing segments before import and to restore raw bytes.
Run inside IDA: File -> Script file...
"""

import json
import base64
import sys

import idaapi
import ida_segment
import ida_bytes
import ida_kernwin
import idc


def import_segments(path, delete_existing=False, restore_bytes=True):
    with open(path, "r") as f:
        data = json.load(f)

    segs = data.get("segments", [])

    if delete_existing:
        # try to delete existing segments - some IDA builds expose helper functions
        try:
            idc.delete_all_segments()
            print("Deleted all existing segments")
        except Exception:
            print("Could not delete existing segments (function not available or failed). Continuing...")

    created = 0
    for sdef in segs:
        start = int(sdef["start"])
        end = int(sdef["end"])
        name = sdef.get("name", "seg")
        sclass = sdef.get("class", "")

        seg = ida_segment.segment_t()
        seg.start_ea = start
        seg.end_ea = end
        # restore basic numeric attributes if present (many are optional)
        if "sel" in sdef:
            seg.sel = int(sdef.get("sel", 0))
        if "perm" in sdef:
            seg.perm = int(sdef.get("perm", 0))
        if "bitness" in sdef:
            seg.bitness = int(sdef.get("bitness", 0))
        if "align" in sdef:
            seg.align = int(sdef.get("align", 0))
        if "comb" in sdef:
            seg.comb = int(sdef.get("comb", 0))
        if "flags" in sdef:
            seg.flags = int(sdef.get("flags", 0))

        # Attempt to add the segment (two common APIs used in IDAPython)
        added = False
        try:
            # add_segm_ex expects a segment_t packed object, a name and class
            added = ida_segment.add_segm_ex(seg, name, sclass, idc.ADDSEG_OR_DIE)
        except Exception:
            # fallback to add_segm(para,start,end,name,sclass,flags) if available
            try:
                para = 0
                added = ida_segment.add_segm(para, start, end, name, sclass, idc.ADDSEG_OR_DIE)
            except Exception:
                added = False

        if not added:
            print("Failed to create segment %s (%#x-%#x). Skipping." % (name, start, end))
            continue

        created += 1

        # get the newly created segment object and apply addressing/bitness if provided
        new_seg = ida_segment.getseg(start)
        if new_seg and "bitness" in sdef:
            try:
                ida_segment.set_segm_addressing(new_seg, int(sdef.get("bitness", 0)))
            except Exception:
                pass

        # restore raw bytes if present and requested
        if restore_bytes and sdef.get("bytes_b64"):
            try:
                data_bytes = base64.b64decode(sdef.get("bytes_b64"))
                if data_bytes:
                    ida_bytes.put_bytes(start, data_bytes)
            except Exception as e:
                print("Failed to restore bytes for segment %s: %s" % (name, e))

        # update segment structure in database
        try:
            if new_seg:
                ida_segment.update_segm(new_seg)
        except Exception:
            pass

        print("Created segment %s (%#x-%#x)" % (name, start, end))

    print("Import completed. Segments created: %d" % created)


if __name__ == "__main__":
    path = ida_kernwin.ask_file(0, "segments_export.json", "Open segments JSON to import")
    if not path:
        print("Cancelled by user.")
        sys.exit(0)

    delete_existing = ida_kernwin.ask_yn(0, "Delete existing segments before import? (Careful)") == 1
    restore_bytes = ida_kernwin.ask_yn(1, "Restore raw bytes when present in JSON?") == 1

    import_segments(path, delete_existing=delete_existing, restore_bytes=restore_bytes)
