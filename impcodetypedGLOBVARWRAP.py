# import_symbols_universal.py
import json
import ida_kernwin
import idc
import ida_funcs
import idaapi

def main():
    fn = ida_kernwin.ask_file(0, "*.json", "Select symbols JSON")
    if not fn:
        print("Canceled")
        return

    with open(fn, 'r', encoding='utf-8') as f:
        symbols = json.load(f)

    imp_cnt      = 0
    func_created = 0
    failed_names = []
    failed_funcs = []

    for ea_str, info in symbols.items():
        ea = int(ea_str, 0)

        # разбираем JSON
        if isinstance(info, str):
            name    = info
            is_func = False
        else:
            name    = info.get("name")
            is_func = info.get("is_func", None)
            if is_func is None and "type" in info:
                t = info["type"]
                is_func = t in (idc.SN_LOCAL, idc.SN_PUBLIC)
            if is_func is None:
                is_func = False

        # если это переменная и имя начинается с "_Z" — убираем первый "_"
        if not is_func and name.startswith("_Z"):
            name = name[1:]

        # 1) пытаемся проставить имя
        if idc.set_name(ea, name, idc.SN_NOWARN):
            imp_cnt += 1

            # 2) если это функция без определения — создаём её
            if is_func and ida_funcs.get_func(ea) is None:
                if ida_funcs.add_func(ea, idaapi.BADADDR):
                    func_created += 1
                else:
                    failed_funcs.append(hex(ea))
        else:
            failed_names.append((hex(ea), name))

    # выводим результат
    print(f"Names imported: {imp_cnt}")
    if failed_names:
        print(f"Failed to set {len(failed_names)} names:")
        for ea, nm in failed_names:
            print(f"  {ea} → {nm}")

    print(f"Functions created: {func_created}")
    if failed_funcs:
        print(f"Failed to create functions at {len(failed_funcs)} addresses:")
        for ea in failed_funcs:
            print(f"  {ea}")

if __name__ == "__main__":
    main()
