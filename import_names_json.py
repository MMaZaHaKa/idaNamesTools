# import_symbols.py
import json
import ida_kernwin
import idc

fn = ida_kernwin.ask_file(0, "*.json", "Select symbols JSON")
if not fn:
    print("Canceled")
    raise SystemExit

with open(fn, 'r', encoding='utf-8') as f:
    symbols = json.load(f)

failed = []
for ea_str, name in symbols.items():
    ea = int(ea_str)
    if not idc.set_name(ea, name, idc.SN_NOWARN):
        failed.append((hex(ea), name))

print(f"Imported {len(symbols)-len(failed)} symbols.")
if failed:
    print(f"Failed to set {len(failed)} names:")
    for ea, name in failed:
        print(f"  {ea} → {name}")
