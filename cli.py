"""
cli.py — Консольный интерфейс системы безопасного обмена файлами

Запуск: python cli.py
"""

import os
import sys
from pathlib import Path
from core import FileShareSystem

system = FileShareSystem()
current_user = None

# ─── Цвета для терминала ─────────────────────────────────────────────────────

R  = "\033[91m"   # красный
G  = "\033[92m"   # зелёный
Y  = "\033[93m"   # жёлтый
B  = "\033[94m"   # синий
C  = "\033[96m"   # голубой
W  = "\033[97m"   # белый
DIM = "\033[2m"
RST = "\033[0m"

def color(text, c): return f"{c}{text}{RST}"
def ok(msg):  print(color(f"  ✓ {msg}", G))
def err(msg): print(color(f"  ✗ {msg}", R))
def info(msg):print(color(f"  ℹ {msg}", C))

# ─── Меню ────────────────────────────────────────────────────────────────────

MENU_GUEST = """
┌─────────────────────────────────────────────┐
│     🔒  Secure File Share  —  CLI           │
├─────────────────────────────────────────────┤
│  1. Войти                                   │
│  2. Зарегистрироваться                      │
│  0. Выход                                   │
└─────────────────────────────────────────────┘"""

MENU_USER = """
┌─────────────────────────────────────────────┐
│  📁  Файлы                                  │
│  1. Показать мои файлы                      │
│  2. Загрузить файл                          │
│  3. Скачать файл                            │
│  4. Удалить файл                            │
├─────────────────────────────────────────────┤
│  🔑  Управление доступом                    │
│  5. Выдать доступ к файлу                   │
│  6. Отозвать доступ                         │
│  7. Показать права файла                    │
├─────────────────────────────────────────────┤
│  📋  Прочее                                 │
│  8. Журнал аудита                           │
│  9. Выйти из аккаунта                       │
│  0. Завершить программу                     │
└─────────────────────────────────────────────┘"""

# ─── Вспомогательные функции ─────────────────────────────────────────────────

def prompt(label, hidden=False):
    if hidden:
        import getpass
        return getpass.getpass(f"  {label}: ")
    return input(f"  {label}: ").strip()

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def header():
    role = system.users.get(current_user, {}).get("role", "?") if current_user else ""
    user_str = color(f"{current_user} [{role}]", Y) if current_user else color("не авторизован", DIM)
    print(f"\n{color('🔒 Secure File Share', B)}  •  {user_str}\n")

# ─── Обработчики команд ──────────────────────────────────────────────────────

def do_login():
    global current_user
    username = prompt("Логин")
    password = prompt("Пароль", hidden=True)
    ok_flag, msg = system.login(username, password)
    if ok_flag:
        current_user = username
        ok(msg)
    else:
        err(msg)

def do_register():
    print(color("  Роли: viewer / editor / admin", DIM))
    username = prompt("Логин")
    password = prompt("Пароль", hidden=True)
    role     = prompt("Роль (viewer)") or "viewer"
    ok_flag, msg = system.register(username, password, role)
    (ok if ok_flag else err)(msg)

def do_list_files():
    files = system.list_files(current_user)
    if not files:
        info("Нет доступных файлов")
        return
    print(f"\n  {'Файл':<25} {'Владелец':<15} {'Права':<10} {'Размер':>8}  {'Дата'}")
    print("  " + "─" * 75)
    for f in files:
        size = f"{f['size']:,} B"
        date = f["uploaded_at"][:16].replace("T", " ")
        perm = color(f["permission"], G if f["is_owner"] else Y)
        print(f"  {f['name']:<25} {f['owner']:<15} {perm:<20} {size:>8}  {date}")

def do_upload():
    path = prompt("Путь к файлу (или имя из текущей папки)")
    filepath = Path(path)
    if not filepath.exists():
        err(f"Файл не найден: {path}")
        return
    data = filepath.read_bytes()
    ok_flag, msg = system.upload_file(current_user, filepath.name, data)
    (ok if ok_flag else err)(msg)

def do_download():
    do_list_files()
    filename = prompt("\n  Имя файла для скачивания")
    dest     = prompt("Сохранить как (Enter = оригинальное имя)") or filename
    ok_flag, result = system.download_file(current_user, filename)
    if ok_flag:
        Path(dest).write_bytes(result)
        ok(f"Файл сохранён: {dest}")
    else:
        err(result)

def do_delete():
    do_list_files()
    filename = prompt("\n  Имя файла для удаления")
    confirm  = prompt(f"Удалить '{filename}'? (да/нет)")
    if confirm.lower() in ("да", "yes", "y", "д"):
        ok_flag, msg = system.delete_file(current_user, filename)
        (ok if ok_flag else err)(msg)
    else:
        info("Отменено")

def do_grant():
    do_list_files()
    filename = prompt("\n  Имя файла")
    target   = prompt("Пользователь, которому выдать доступ")
    perm     = prompt("Права (read / write)")
    ok_flag, msg = system.grant_access(current_user, filename, target, perm)
    (ok if ok_flag else err)(msg)

def do_revoke():
    filename = prompt("Имя файла")
    target   = prompt("Пользователь, у которого отозвать доступ")
    ok_flag, msg = system.revoke_access(current_user, filename, target)
    (ok if ok_flag else err)(msg)

def do_show_acl():
    filename = prompt("Имя файла")
    acl = system.get_acl(current_user, filename)
    if acl is None:
        err("Нет доступа к правам этого файла")
    elif not acl:
        info("Нет дополнительных прав (только владелец)")
    else:
        print(f"\n  {'Пользователь':<20} Права")
        print("  " + "─" * 35)
        for user, perm in acl.items():
            print(f"  {user:<20} {color(perm, G)}")

def do_logs():
    user_role = system.users.get(current_user, {}).get("role")
    logs = system.get_logs(30)
    if not logs:
        info("Журнал пуст")
        return
    print(f"\n  {color('Последние записи журнала аудита:', C)}")
    print("  " + "─" * 65)
    for line in logs:
        # Цветовая маркировка
        if "DENIED" in line:
            print("  " + color(line, R))
        elif "LOGIN_FAIL" in line:
            print("  " + color(line, Y))
        elif "DELETE" in line:
            print("  " + color(line, Y))
        else:
            print("  " + color(line, DIM))

# ─── Главный цикл ─────────────────────────────────────────────────────────────

def main():
    global current_user
    print(color("\n  Добро пожаловать в Secure File Share!", B))
    print(color("  Аккаунт по умолчанию: admin / admin123\n", DIM))

    while True:
        header()
        if not current_user:
            print(MENU_GUEST)
            choice = input("  Выберите действие: ").strip()
            if   choice == "1": do_login()
            elif choice == "2": do_register()
            elif choice == "0": print(color("\n  До свидания!\n", C)); sys.exit()
            else: err("Неверный выбор")
        else:
            print(MENU_USER)
            choice = input("  Выберите действие: ").strip()
            if   choice == "1": do_list_files()
            elif choice == "2": do_upload()
            elif choice == "3": do_download()
            elif choice == "4": do_delete()
            elif choice == "5": do_grant()
            elif choice == "6": do_revoke()
            elif choice == "7": do_show_acl()
            elif choice == "8": do_logs()
            elif choice == "9":
                info(f"Выход из аккаунта '{current_user}'")
                current_user = None
            elif choice == "0":
                print(color("\n  До свидания!\n", C))
                sys.exit()
            else:
                err("Неверный выбор")

        input(color("\n  [Enter] — продолжить...", DIM))

if __name__ == "__main__":
    main()
