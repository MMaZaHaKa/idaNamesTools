"""
IDA Pro 7.6 IDAPython script
Создаёт/обновляет sym-файл (PPSSPP style) из функций, проанализированных в IDA.
Поведение:
 - Спрашивает, есть ли входной sym-файл.
 - Если выбран входной sym: парсит его, заменяет/обновляет имена на те, что заданы в IDA (деманглирует).
   - Если деманглированное имя уже встречалось (перегрузки) добавляет суффикс _1, _2...
   - Если функция есть в IDA, но в sym её нет — добавляет запись с префиксом NOSYM_.
 - Если входной sym НЕ выбран: экспортирует все функции из IDA.
 - Окно сохранения с дефолтным именем: idasym.sym

Формат строк в sym (пример):
08804000 z_un_08804000,0080
08804080 z_un_08804080,0038
088040B8 z_un_088040b8,0050

Примечания:
 - Скрипт пытается использовать встроенные деманглеры IDA (idaapi/idc). Если деманглинг
   недоступен — имя остаётся как есть.
 - Адреса сравниваются по началу функции (ea).
 - Размер/offset записывается в 4-значном HEX (ниже примера — 0080).

Как использовать: открыть скрипт в IDA и выполнить (File -> Script file... или через консоль).
"""

from __future__ import print_function
import ida_kernwin
import idautils
import ida_funcs
import idaapi
import idc
import os
import sys


def demangle_name_try(name):
    """Попытаться деманглировать имя с помощью доступных API IDA.
    Если не удалось — вернуть исходное имя.
    """
    if not name:
        return name
    # try idaapi.demangle_name (older/newer API differences)
    try:
        if hasattr(idaapi, 'demangle_name'):
            try:
                # some IDA versions expect second parameter flags; try both
                dem = idaapi.demangle_name(name)
                if dem:
                    return dem
            except Exception:
                try:
                    dem = idaapi.demangle_name(name, 0)
                    if dem:
                        return dem
                except Exception:
                    pass
    except Exception:
        pass

    # try idc.demangle_name
    try:
        if hasattr(idc, 'demangle_name'):
            try:
                dem = idc.demangle_name(name, 0)
                if dem:
                    return dem
            except Exception:
                try:
                    dem = idc.demangle_name(name)
                    if dem:
                        return dem
                except Exception:
                    pass
    except Exception:
        pass

    # fallback: try idaapi.get_short_demangled_name if present
    try:
        if hasattr(idaapi, 'get_short_demangled_name'):
            dem = idaapi.get_short_demangled_name(name)
            if dem:
                return dem
    except Exception:
        pass

    # nothing worked
    return name


def format_addr(ea):
    # 8 hex digits uppercase like example
    return "{:08X}".format(ea)


def format_size(sz):
    # 4 hex digits lowercase as in example
    return "{:04x}".format(sz)


def parse_sym_file(path):
    entries = {}  # ea -> (name_from_sym, size_from_sym)
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith('#'):
                    continue
                parts = ln.split()
                if len(parts) < 2:
                    continue
                addr_s = parts[0]
                rest = parts[1]
                # rest like name,offset
                if ',' in rest:
                    name_part, off_part = rest.split(',', 1)
                else:
                    name_part = rest
                    off_part = '0'
                try:
                    ea = int(addr_s, 16)
                except Exception:
                    continue
                try:
                    size = int(off_part, 16)
                except Exception:
                    # try decimal
                    try:
                        size = int(off_part)
                    except Exception:
                        size = 0
                entries[ea] = (name_part, size)
    except Exception as e:
        ida_kernwin.msg('Failed to read sym file: %s\n' % str(e))
    return entries


def collect_ida_functions():
    # return dict ea->(demangled_name, size)
    funcs = {}
    for ea in idautils.Functions():
        try:
            name = idc.get_func_name(ea)
        except Exception:
            try:
                name = ida_funcs.get_func_name(ea)
            except Exception:
                name = None
        if not name:
            continue
        dem = demangle_name_try(name)
        # clean demangled: strip leading/trailing spaces
        dem = dem.strip()
        # replace commas and newlines
        dem = dem.replace(',', '_').replace('\n', '_')
        # get size
        f = ida_funcs.get_func(ea)
        if f:
            size = f.end_ea - f.start_ea
        else:
            # approximate: next head - ea
            try:
                nxt = idc.find_nxt_function(ea)
                if nxt and nxt > ea:
                    size = nxt - ea
                else:
                    size = 0
            except Exception:
                size = 0
        funcs[ea] = (dem, size)
    return funcs


def make_unique(name, used):
    """Если name уже используется, добавляем суффикс _1, _2... и возвращаем новую версию.
    used — dict name->count
    """
    if name not in used:
        used[name] = 1
        return name
    else:
        cnt = used[name]
        newname = f"{name}_{cnt}"
        # increment until unique
        while newname in used:
            cnt += 1
            newname = f"{name}_{cnt}"
        used[name] = cnt + 1
        used[newname] = 1
        return newname


def build_output_entries(sym_entries, ida_funcs_map):
    """
    sym_entries: dict ea -> (sym_name, sym_size)
    ida_funcs_map: dict ea -> (dem_name, size)
    returns dict ea -> (out_name, out_size)
    """
    out = {}
    used_names = {}

    # start from existing sym entries: if IDA has a function at same ea — replace name with IDA's demangled name
    for ea, (sym_name, sym_size) in sym_entries.items():
        if ea in ida_funcs_map:
            dem_name, size = ida_funcs_map[ea]
            # ensure uniqueness
            dem_name = make_unique(dem_name, used_names)
            out[ea] = (dem_name, size if size else sym_size)
            # mark that we've consumed this IDA function
            # we'll drop it from ida_funcs_map processed later
        else:
            # no IDA function at this ea — keep original sym
            out[ea] = (sym_name, sym_size)

    # now, for IDA functions not present in sym, add them with NOSYM_ prefix
    for ea, (dem_name, size) in ida_funcs_map.items():
        if ea in out:
            # already handled
            continue
        name_with_prefix = 'NOSYM_' + dem_name
        name_with_prefix = make_unique(name_with_prefix, used_names)
        out[ea] = (name_with_prefix, size)

    return out


def write_sym_file(path, entries):
    # entries: dict ea->(name, size)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            # sort by address ascending
            for ea in sorted(entries.keys()):
                name, size = entries[ea]
                f.write(f"{format_addr(ea)} {name},{format_size(size)}\n")
        ida_kernwin.msg('Wrote sym file: %s\n' % path)
        return True
    except Exception as e:
        ida_kernwin.msg('Failed to write sym file: %s\n' % str(e))
        return False


def main():
    # ask user whether to open existing sym file
    yn = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, 'Есть ли входной sym-файл для обновления? (Yes = открыть)')
    sym_entries = {}
    if yn == ida_kernwin.ASKBTN_YES:
        # ask open file
        path = ida_kernwin.ask_file(0, "*.sym", 'Open sym file')
        if not path:
            ida_kernwin.msg('No input file selected — will export only IDA functions.\n')
        else:
            path = os.path.normpath(path)
            if os.path.exists(path):
                sym_entries = parse_sym_file(path)
                ida_kernwin.msg('Parsed %d entries from sym.\n' % len(sym_entries))
            else:
                ida_kernwin.msg('Selected file does not exist — continuing without it.\n')

    # collect IDA functions
    ida_map = collect_ida_functions()
    ida_kernwin.msg('Collected %d functions from IDA.\n' % len(ida_map))

    if sym_entries:
        out_entries = build_output_entries(sym_entries, ida_map)
    else:
        # export all IDA functions directly — ensure unique names
        used = {}
        out_entries = {}
        for ea, (dem, size) in ida_map.items():
            name = make_unique(dem, used)
            out_entries[ea] = (name, size)

    # ask save path
    default_name = 'idasym.sym'
    save_path = ida_kernwin.ask_file(1, default_name, 'Save sym file as')
    if not save_path:
        ida_kernwin.msg('Save cancelled.\n')
        return
    save_path = os.path.normpath(save_path)

    ok = write_sym_file(save_path, out_entries)
    if ok:
        ida_kernwin.msg('Done. Saved to: %s\n' % save_path)
    else:
        ida_kernwin.msg('Failed to save file.\n')


if __name__ == '__main__':
    main()
