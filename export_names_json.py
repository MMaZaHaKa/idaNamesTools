# export_symbols.py
import json
import idautils
import idc

# Получаем полный путь текущей БД, заменяем расширение на .json
idb_path = idc.get_idb_path()                   # <-- was GetIdbPath()
out = idb_path.rsplit('.', 1)[0] + "_sym.json"

symbols = { str(ea): name for ea, name in idautils.Names() }

with open(out, 'w', encoding='utf-8') as f:
    json.dump(symbols, f, indent=2, ensure_ascii=False)

print(f"Exported {len(symbols)} symbols to {out}")
