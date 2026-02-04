# remote_jump.py
# IDA Pro 7.6 (IDAPython). Запускается в фоне, слушает TCP и при получении 4 байт (uint32 little-endian)
# выполняет ida_kernwin.jumpto(addr) в GUI-потоке.
#
# Usage:
#  - В IDA Python консоли:
#       import remote_jump
#       remote_jump.start_listener(host='127.0.0.1', port=27310)
#  - Остановить:
#       remote_jump.stop_listener()

import socket
import struct
import threading
import time

import ida_kernwin
import idaapi

# Глобальные переменные для контроля потока
_listener_thread = None
_stop_event = None

def _safe_jumpto(addr):
    """
    Jumpto должен вызываться в основном GUI-потоке IDA.
    Пытаемся использовать execute_sync (доступно в современных IDA), иначе просто вызвать jumpto.
    """
    try:
        # try to call via execute_sync so GUI changes are safe
        # MFF_WRITE — обычно для операций, меняющих GUI. Если не определено — fallback.
        flags = getattr(ida_kernwin, "MFF_WRITE", 0)
        ida_kernwin.execute_sync(lambda: ida_kernwin.jumpto(addr), flags)
    except Exception:
        # fallback: прямой вызов (иногда работает, но не гарантированно потокобезопасно)
        try:
            ida_kernwin.jumpto(addr)
        except Exception as e:
            ida_kernwin.msg("[remote_jump] jump failed: %s\n" % str(e))

def _listener_worker(host, port, reconnect_delay=2.0):
    """
    Worker thread: подключается к host:port, затем ждет 4-байтных сообщений (uint32 LE).
    При получении вызывает _safe_jumpto.
    Переподключается при обрыве.
    """
    global _stop_event
    ida_kernwin.msg("[remote_jump] listener thread starting, target %s:%d\n" % (host, port))

    while not _stop_event.is_set():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(5.0)
            s.connect((host, port))
            s.settimeout(None)  # blocking for recv
            ida_kernwin.msg("[remote_jump] connected to %s:%d\n" % (host, port))
            # При подключении — читаем по 4 байта
            while not _stop_event.is_set():
                data = b''
                # читаем ровно 4 байта
                while len(data) < 4 and not _stop_event.is_set():
                    chunk = s.recv(4 - len(data))
                    if not chunk:
                        raise ConnectionError("peer closed")
                    data += chunk
                if _stop_event.is_set():
                    break
                if len(data) != 4:
                    raise ConnectionError("invalid read length")
                addr = struct.unpack('<I', data)[0]  # little-endian uint32
                ida_kernwin.msg("[remote_jump] got addr: 0x%08X\n" % addr)
                # выполняем jump в GUI-потоке
                _safe_jumpto(addr)
            s.close()
        except Exception as e:
            try:
                s.close()
            except:
                pass
            ida_kernwin.msg("[remote_jump] connection error: %s — reconnecting in %.1fs\n" % (str(e), reconnect_delay))
            # ждем перед новой попыткой (но следим на stop)
            t0 = time.time()
            while (time.time() - t0) < reconnect_delay and not _stop_event.is_set():
                time.sleep(0.1)

    ida_kernwin.msg("[remote_jump] listener thread stopped\n")

def start_listener(host='127.0.0.1', port=27312):
    """
    Запустить фоновый слушатель. Ничего не возвращает.
    Если уже запущен — ничего не делает.
    """
    global _listener_thread, _stop_event
    if _listener_thread and _listener_thread.is_alive():
        ida_kernwin.msg("[remote_jump] already running\n")
        return
    _stop_event = threading.Event()
    _listener_thread = threading.Thread(target=_listener_worker, args=(host, port), daemon=True)
    _listener_thread.start()
    ida_kernwin.msg("[remote_jump] started (host=%s port=%d)\n" % (host, port))

def stop_listener():
    """Остановить слушатель (безопасно)."""
    global _listener_thread, _stop_event
    if not _listener_thread:
        ida_kernwin.msg("[remote_jump] not running\n")
        return
    _stop_event.set()
    # подождём немножко чтобы поток завершился
    _listener_thread.join(timeout=2.0)
    if _listener_thread.is_alive():
        ida_kernwin.msg("[remote_jump] thread still alive (will stop when IDA exits)\n")
    else:
        ida_kernwin.msg("[remote_jump] stopped\n")
    _listener_thread = None
    _stop_event = None

if __name__ == "__main__":
    ida_kernwin.msg("[remote_jump] loaded.\n")
    start_listener(host='127.0.0.1', port=27310)
