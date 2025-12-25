#!/usr/bin/env python3

import sys
import ctypes


def is_admin():
    """Проверка прав администратора"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def check_windows():
    """Проверка, что запуск на Windows"""
    if sys.platform != 'win32':
        print("Этот антивирус разработан специально для Windows!")
        print("Требуется Windows 10/11 для работы.")
        input("Нажмите Enter для выхода...")
        sys.exit(1)


def check_python_version():
    """Проверка версии Python"""
    if sys.version_info < (3, 8):
        print("Требуется Python 3.8 или выше!")
        input("Нажмите Enter для выхода...")
        sys.exit(1)


def main():
    """Главная функция запуска"""
    print("=" * 50)
    print("WindowsAV - Антивирус для Windows")
    print("Версия 1.0.0")
    print("=" * 50)

    # Проверки
    check_windows()
    check_python_version()

    # Проверка прав администратора
    if not is_admin():
        print("ВНИМАНИЕ: Программа запущена без прав администратора.")

    # Запуск GUI
    try:
        from gui import WindowsAVApp
        app = WindowsAVApp(sys.argv)
        app.run()
    except ImportError as e:
        print(f"Ошибка импорта: {e}")
        print("Установите необходимые библиотеки:")
        print("pip install PySide6 pefile psutil pywin32 requests wmi")
        input("Нажмите Enter для выхода...")
        sys.exit(1)


if __name__ == "__main__":
    main()
