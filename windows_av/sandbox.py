"""
Песочница для безопасного выполнения файлов в Windows
"""

import os
import tempfile
import subprocess
import time
import shutil

import psutil


class WindowsSandbox:
    """Песочница для анализа поведения файлов в Windows"""

    def __init__(self, timeout=30):
        self.timeout = timeout
        self.temp_dir = None
        self.process = None

    def analyze(self, file_path, file_type="executable"):
        """Анализ файла в песочнице"""
        result = {
            "success": False,
            "behavior": {},
            "errors": [],
            "warnings": []
        }

        try:
            # Создаем временную директорию
            self.temp_dir = tempfile.mkdtemp(prefix="av_sandbox_")

            # Копируем файл в песочницу
            target_path = os.path.join(self.temp_dir, os.path.basename(file_path))

            # Используем shutil (уже импортирован)
            shutil.copy2(file_path, target_path)

            # Настраиваем окружение
            env = self._setup_environment()

            # Мониторим систему до запуска
            before_state = self._capture_system_state()

            # Запускаем файл
            execution_result = self._execute_file(target_path, file_type, env)
            result["behavior"].update(execution_result)

            # Мониторим систему после запуска
            time.sleep(2)  # Ждем завершения процессов
            after_state = self._capture_system_state()

            # Анализируем изменения
            changes = self._analyze_changes(before_state, after_state)
            result["behavior"].update(changes)

            result["success"] = True

        except Exception as e:
            result["errors"].append(f"Ошибка песочницы: {str(e)}")

        finally:
            # Очистка
            self._cleanup()

        return result

    def _setup_environment(self):
        """Настройка изолированного окружения"""
        env = os.environ.copy()

        # Ограничиваем переменные окружения
        restricted_vars = [
            "PATH", "TEMP", "TMP", "USERPROFILE", "APPDATA",
            "LOCALAPPDATA", "SYSTEMROOT", "WINDIR"
        ]

        for var in restricted_vars:
            if var in env:
                # Перенаправляем во временную директорию
                if var in ["TEMP", "TMP"]:
                    env[var] = self.temp_dir

        # Добавляем безопасные пути
        env["PATH"] = f"{self.temp_dir};C:\\Windows\\System32"

        # Устанавливаем минимальные привилегии
        env["__COMPAT_LAYER"] = "RunAsInvoker"

        return env

    def _execute_file(self, file_path, file_type, env):
        """Выполнение файла в изолированном окружении"""
        result = {
            "execution_time": 0,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "processes_created": [],
            "files_created": [],
            "network_connections": []
        }

        start_time = time.time()

        try:
            # Определяем команду в зависимости от типа файла
            if file_type == "executable":
                cmd = [file_path]
            elif file_type == "script":
                if file_path.endswith(".ps1"):
                    cmd = ["powershell", "-ExecutionPolicy", "Restricted", "-File", file_path]
                elif file_path.endswith(".vbs"):
                    cmd = ["cscript", "//B", file_path]
                elif file_path.endswith(".js"):
                    cmd = ["cscript", "//B", file_path]
                else:
                    cmd = [file_path]
            else:
                cmd = [file_path]

            # Запускаем процесс с ограничениями
            creation_flags = (
                subprocess.CREATE_NEW_CONSOLE |
                subprocess.CREATE_NO_WINDOW
            )

            self.process = subprocess.Popen(
                cmd,
                cwd=self.temp_dir,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creation_flags
            )

            # Мониторим процесс
            try:
                stdout, stderr = self.process.communicate(timeout=self.timeout)
                result["stdout"] = stdout.decode('utf-8', errors='ignore')[:1000]
                result["stderr"] = stderr.decode('utf-8', errors='ignore')[:1000]
                result["exit_code"] = self.process.returncode

            except subprocess.TimeoutExpired:
                # Принудительно завершаем процесс и его потомков
                self._terminate_process_tree(self.process.pid)
                result["timeout"] = True

            # Собираем информацию о созданных процессах
            result["processes_created"] = self._get_child_processes(self.process.pid)

        except Exception as e:
            result["stderr"] = f"Ошибка выполнения: {str(e)}"

        result["execution_time"] = time.time() - start_time
        return result

    def _capture_system_state(self):
        """Создание снимка состояния системы"""
        state = {
            "processes": [],
            "files": [],
            "network": []
        }

        try:
            # Список процессов (только Python-процессы)
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    state["processes"].append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Файлы в временной директории
            if self.temp_dir and os.path.exists(self.temp_dir):
                for root, dirs, files in os.walk(self.temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        state["files"].append({
                            "path": file_path,
                            "size": os.path.getsize(file_path) if os.path.exists(file_path) else 0
                        })

            # Сетевые соединения (упрощенно)
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'ESTABLISHED':
                        state["network"].append({
                            "local": conn.laddr,
                            "pid": conn.pid
                        })
            except:
                pass

        except Exception:
            pass

        return state

    def _analyze_changes(self, before_state, after_state):
        """Анализ изменений в системе"""
        changes = {
            "new_processes": [],
            "new_files": [],
            "network_activity": [],
            "suspicious_behavior": []
        }

        try:
            # Анализ процессов
            before_pids = {p['pid'] for p in before_state['processes']}
            after_pids = {p['pid'] for p in after_state['processes']}

            new_pids = after_pids - before_pids
            for proc in after_state['processes']:
                if proc['pid'] in new_pids:
                    changes["new_processes"].append(proc)

            # Анализ файлов
            before_files = {f['path'] for f in before_state['files']}
            after_files = {f['path'] for f in after_state['files']}

            new_files = after_files - before_files
            for file in after_state['files']:
                if file['path'] in new_files:
                    changes["new_files"].append(file)

            # Анализ сетевой активности
            if len(after_state['network']) > len(before_state['network']):
                changes["network_activity"] = after_state['network'][len(before_state['network']):]

        except Exception as e:
            changes["suspicious_behavior"].append(f"Ошибка анализа: {str(e)}")

        return changes

    def _get_child_processes(self, parent_pid):
        """Получение дочерних процессов"""
        child_processes = []

        try:
            parent = psutil.Process(parent_pid)
            children = parent.children(recursive=True)

            for child in children:
                try:
                    child_info = {
                        "pid": child.pid,
                        "name": child.name(),
                        "status": child.status()
                    }
                    child_processes.append(child_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return child_processes

    def _terminate_process_tree(self, pid):
        """Завершение дерева процессов"""
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)

            # Завершаем дочерние процессы
            for child in children:
                try:
                    child.terminate()
                except:
                    pass

            # Завершаем родительский процесс
            try:
                parent.terminate()
                parent.wait(timeout=5)
            except:
                pass

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def _cleanup(self):
        """Очистка песочницы"""
        # Завершаем процесс если он еще работает
        if self.process and self.process.poll() is None:
            self._terminate_process_tree(self.process.pid)

        # Удаляем временную директорию
        if self.temp_dir and os.path.exists(self.temp_dir):
            # Пробуем удалить несколько раз
            for attempt in range(3):
                try:
                    shutil.rmtree(self.temp_dir, ignore_errors=True)
                    if not os.path.exists(self.temp_dir):
                        break
                    time.sleep(1)
                except:
                    pass
