"""
Сканирующий движок WindowsAV
"""

import os
import hashlib
import pefile
import time
from pathlib import Path
from datetime import datetime
import psutil


class WindowsAVScanner:
    """Основной сканирующий движок для Windows"""

    def __init__(self, signature_manager):
        self.signature_manager = signature_manager
        self.scan_results = {
            "total_scanned": 0,
            "threats_found": 0,
            "threats": [],
            "scan_time": 0,
            "scan_type": ""
        }

        # Системные пути для быстрого сканирования
        self.system_paths = [
            os.environ.get("SYSTEMROOT", "C:\\Windows"),
            os.environ.get("PROGRAMFILES", "C:\\Program Files"),
            os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"),
            os.environ.get("APPDATA", os.path.join(os.environ["USERPROFILE"], "AppData\\Roaming")),
            os.environ.get("LOCALAPPDATA", os.path.join(os.environ["USERPROFILE"], "AppData\\Local")),
            os.environ.get("TEMP", os.path.join(os.environ["USERPROFILE"], "AppData\\Local\\Temp")),
        ]

        # Расширения для проверки
        self.executable_extensions = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".ps1", ".vbs", ".js"}

    def scan_path(self, path, scan_type="quick", progress_callback=None):
        """Сканирование указанного пути"""
        start_time = time.time()
        self.scan_results = {
            "total_scanned": 0,
            "threats_found": 0,
            "threats": [],
            "scan_time": 0,
            "scan_type": scan_type
        }

        try:
            if scan_type == "quick":
                self._quick_scan(progress_callback)
            elif scan_type == "full":
                self._full_scan(progress_callback)
            else:
                self._custom_scan(path, progress_callback)

        except Exception as e:
            raise Exception(f"Ошибка сканирования: {str(e)}")

        self.scan_results["scan_time"] = time.time() - start_time
        return self.scan_results

    def _quick_scan(self, progress_callback):
        """Быстрое сканирование системных областей"""
        files_to_scan = []

        # Собираем файлы из системных путей
        for sys_path in self.system_paths:
            if os.path.exists(sys_path):
                for root, dirs, files in os.walk(sys_path, topdown=True):
                    # Пропускаем слишком глубокие директории
                    if root.count(os.sep) - sys_path.count(os.sep) > 3:
                        dirs[:] = []
                        continue

                    for file in files:
                        if Path(file).suffix.lower() in self.executable_extensions:
                            files_to_scan.append(os.path.join(root, file))

        self._scan_file_list(files_to_scan[:1000], progress_callback)  # Ограничиваем 1000 файлов

    def _full_scan(self, progress_callback):
        """Полное сканирование текущего диска"""
        import ctypes

        files_to_scan = []

        # Получаем текущий диск
        current_drive = os.path.splitdrive(os.getcwd())[0]

        if os.path.exists(current_drive):
            try:
                for root, dirs, files in os.walk(current_drive, topdown=True):
                    # Пропускаем системные директории
                    if "Windows" in root or "$" in root:
                        dirs[:] = []
                        continue

                    for file in files:
                        file_path = os.path.join(root, file)
                        files_to_scan.append(file_path)

                        if len(files_to_scan) > 5000:  # Ограничиваем для теста
                            break
            except:
                pass

        self._scan_file_list(files_to_scan[:2000], progress_callback)

    def _custom_scan(self, path, progress_callback):
        """Выборочное сканирование указанного пути"""
        files_to_scan = []

        if os.path.isfile(path):
            files_to_scan.append(path)
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    files_to_scan.append(file_path)

        self._scan_file_list(files_to_scan[:500], progress_callback)

    def _scan_file_list(self, file_list, progress_callback):
        """Сканирование списка файлов"""
        total_files = len(file_list)

        for i, file_path in enumerate(file_list):
            if progress_callback:
                progress_callback(i + 1, total_files, file_path)

            try:
                self._scan_file(file_path)
            except Exception as e:
                # Пропускаем файлы с ошибками доступа
                continue

            self.scan_results["total_scanned"] += 1

    def _scan_file(self, file_path):
        """Сканирование одного файла"""
        try:
            # Проверяем размер файла
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:  # 50MB
                return

            # Получаем хеши файла
            file_hash = self._calculate_file_hash(file_path)

            # Проверяем по базе сигнатур
            threat_info = self.signature_manager.check_hash(file_hash)

            if not threat_info:
                # Если нет в базе хешей, проверяем содержимое
                with open(file_path, "rb") as f:
                    file_data = f.read(512 * 1024)  # Читаем первые 512KB

                threat_info = self.signature_manager.check_content(file_data)

                # Анализ PE файлов
                if Path(file_path).suffix.lower() in {".exe", ".dll", ".sys"}:
                    try:
                        pe_threat = self._analyze_pe_file(file_path, file_data)
                        if pe_threat:
                            threat_info = threat_info or {}
                            threat_info.update(pe_threat)
                    except:
                        pass

            if threat_info:
                self.scan_results["threats_found"] += 1
                self.scan_results["threats"].append({
                    "path": file_path,
                    "name": threat_info.get("name", "Unknown Threat"),
                    "type": threat_info.get("type", "Virus"),
                    "severity": threat_info.get("severity", "Medium"),
                    "description": threat_info.get("description", ""),
                    "date": datetime.now().strftime("%d.%m.%Y %H:%M"),
                    "status": "Обнаружено",
                    "hash": file_hash
                })

        except Exception:
            pass

    def _calculate_file_hash(self, file_path):
        """Вычисление SHA256 хеша файла"""
        sha256_hash = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return ""

    def _analyze_pe_file(self, file_path, file_data):
        """Анализ PE файла"""
        try:
            pe = pefile.PE(data=file_data, fast_load=True)

            suspicious_indicators = []

            # Проверка секций
            for section in pe.sections:
                try:
                    section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')

                    # Подозрительные характеристики секций
                    if section.Characteristics & 0xE0000020:  # EXECUTE, READ, WRITE
                        suspicious_indicators.append(f"Секция {section_name} имеет атрибуты RWX")
                except:
                    continue

            # Проверка импортов
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                suspicious_imports = [
                    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
                    "CreateProcess", "ShellExecute", "WinExec",
                    "URLDownloadToFile", "InternetOpenUrl"
                ]

                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        dll_name = entry.dll.decode('utf-8', errors='ignore').lower()

                        for imp in entry.imports:
                            if imp.name:
                                import_name = imp.name.decode('utf-8', errors='ignore')
                                if import_name in suspicious_imports:
                                    suspicious_indicators.append(f"Подозрительный импорт: {import_name}")
                    except:
                        continue

            if suspicious_indicators:
                return {
                    "name": "Подозрительный PE файл",
                    "type": "Trojan",
                    "severity": "High",
                    "description": "; ".join(suspicious_indicators[:3])
                }

        except Exception:
            pass

        return None

    def scan_memory(self):
        """Сканирование оперативной памяти"""
        memory_threats = []

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_info = proc.info

                # Проверяем подозрительные имена процессов
                suspicious_names = [
                    "miner", "xmrig", "cpuminer", "ethminer",
                    "inject", "injector", "loader", "keylogger"
                ]

                proc_name = proc_info['name'].lower()
                for suspicious in suspicious_names:
                    if suspicious in proc_name:
                        memory_threats.append({
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "type": "Memory Threat",
                            "description": f"Подозрительный процесс: {proc_info['name']}"
                        })
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return memory_threats
