# export_symbols_with_flag.py
import json
import idautils
import ida_funcs
import idc

symbols = {}
for ea, name in idautils.Names():
    # проверяем, является ли ea началом функции
    is_func = ida_funcs.get_func(ea) is not None
    symbols[str(ea)] = {"name": name, "is_func": is_func}

# сохраняем рядом с .idb
out = idc.get_idb_path().rsplit('.',1)[0] + "_symflag.json"
with open(out, 'w', encoding='utf-8') as f:
    json.dump(symbols, f, indent=2, ensure_ascii=False)

print(f"Exported {len(symbols)} symbols (with is_func flag) to {out}")
