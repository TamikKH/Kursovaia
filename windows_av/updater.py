"""
Менеджер обновлений для WindowsAV
"""

import requests
import json
import hashlib
import zipfile
from datetime import datetime
from pathlib import Path


class UpdateManager:
    """Управление обновлением антивирусных баз"""
    
    def __init__(self, data_dir, signature_manager):
        self.data_dir = Path(data_dir)
        self.signature_manager = signature_manager

        self.update_servers = [
            "https://windows-av-updates.example.com",
            "https://backup-updates.example.com"
        ]

        self.update_info_file = self.data_dir / "update_info.json"
        self._load_update_info()
    
    def _load_update_info(self):
        """Загрузка информации об обновлениях"""
        if self.update_info_file.exists():
            try:
                with open(self.update_info_file, 'r', encoding='utf-8') as f:
                    self.update_info = json.load(f)
            except:
                self.update_info = {
                    "last_update": None,
                    "update_attempts": 0,
                    "signature_version": "1.0.0",
                    "engine_version": "1.0.0"
                }
        else:
            self.update_info = {
                "last_update": None,
                "update_attempts": 0,
                "signature_version": "1.0.0",
                "engine_version": "1.0.0"
            }
    
    def _save_update_info(self):
        """Сохранение информации об обновлениях"""
        with open(self.update_info_file, 'w', encoding='utf-8') as f:
            json.dump(self.update_info, f, indent=2, ensure_ascii=False)
    
    def check_for_updates(self):
        """Проверка наличия обновлений"""
        try:
            for server in self.update_servers:
                try:
                    response = requests.get(
                        f"{server}/update_check.json",
                        timeout=10,
                        headers={"User-Agent": "WindowsAV/1.0"}
                    )
                    
                    if response.status_code == 200:
                        update_data = response.json()
                        
                        current_version = self.update_info["signature_version"]
                        new_version = update_data.get("signature_version", current_version)
                        
                        if self._compare_versions(new_version, current_version) > 0:
                            return {
                                "available": True,
                                "current_version": current_version,
                                "new_version": new_version,
                                "size": update_data.get("update_size", 0),
                                "description": update_data.get("description", ""),
                                "critical": update_data.get("critical", False)
                            }
                        
                        break
                        
                except requests.RequestException:
                    continue
            
            return {"available": False}
            
        except Exception as e:
            return {"available": False, "error": str(e)}
    
    def update_all(self, progress_callback=None):
        """Полное обновление всех компонентов"""
        try:
            if progress_callback:
                progress_callback("Проверка обновлений...", 10)
            
            update_info = self.check_for_updates()
            
            if not update_info.get("available", False):
                return False, "Обновления не требуются"

            if progress_callback:
                progress_callback("Загрузка обновлений...", 30)
            
            update_file = self._download_update(update_info)
            
            if not update_file:
                return False, "Не удалось загрузить обновление"

            if progress_callback:
                progress_callback("Установка обновлений...", 70)
            
            success, message = self._apply_update(update_file, update_info)
            
            if success:
                self.update_info["last_update"] = datetime.now().isoformat()
                self.update_info["signature_version"] = update_info["new_version"]
                self.update_info["update_attempts"] = 0
                self._save_update_info()
                
                if progress_callback:
                    progress_callback("Обновление завершено", 100)
                
                return True, f"Успешно обновлено до версии {update_info['new_version']}"
            else:
                return False, message
            
        except Exception as e:
            self.update_info["update_attempts"] = self.update_info.get("update_attempts", 0) + 1
            self._save_update_info()
            
            return False, f"Ошибка обновления: {str(e)}"
    
    def _download_update(self, update_info):
        """Загрузка обновления"""
        temp_dir = self.data_dir / "temp_updates"
        temp_dir.mkdir(exist_ok=True)
        
        for server in self.update_servers:
            try:
                update_url = f"{server}/updates/v{update_info['new_version']}.zip"
                
                response = requests.get(
                    update_url,
                    stream=True,
                    timeout=30,
                    headers={"User-Agent": "WindowsAV/1.0"}
                )
                
                if response.status_code == 200:
                    update_file = temp_dir / f"update_{update_info['new_version']}.zip"
                    
                    total_size = int(response.headers.get('content-length', 0))
                    downloaded = 0
                    
                    with open(update_file, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                                downloaded += len(chunk)

                    if self._verify_update_file(update_file, update_info):
                        return update_file
                    else:
                        update_file.unlink(missing_ok=True)
                        
            except requests.RequestException:
                continue
        
        return None
    
    def _verify_update_file(self, update_file, update_info):
        """Проверка целостности файла обновления"""
        try:
            # Проверяем размер
            file_size = update_file.stat().st_size
            
            if "size" in update_info and update_info["size"] > 0:
                if abs(file_size - update_info["size"]) > 1024:  # Допуск 1KB
                    return False
            
            # Проверяем хеш если есть
            if "hash" in update_info:
                file_hash = self._calculate_file_hash(update_file)
                if file_hash != update_info["hash"]:
                    return False
            
            # Проверяем архив
            try:
                with zipfile.ZipFile(update_file, 'r') as zipf:
                    # Проверяем структуру
                    required_files = ["signatures.json", "manifest.json"]
                    for required in required_files:
                        if required not in zipf.namelist():
                            return False
            except zipfile.BadZipFile:
                return False
            
            return True
            
        except Exception:
            return False
    
    def _apply_update(self, update_file, update_info):
        """Применение обновления"""
        try:
            extract_dir = self.data_dir / "updates"
            extract_dir.mkdir(exist_ok=True)
            
            # Распаковываем архив
            with zipfile.ZipFile(update_file, 'r') as zipf:
                zipf.extractall(extract_dir)
            
            # Читаем манифест
            manifest_file = extract_dir / "manifest.json"
            if manifest_file.exists():
                with open(manifest_file, 'r', encoding='utf-8') as f:
                    manifest = json.load(f)
            
            # Обновляем сигнатуры
            signatures_file = extract_dir / "signatures.json"
            if signatures_file.exists():
                with open(signatures_file, 'r', encoding='utf-8') as f:
                    signatures = json.load(f)
                
                # Обновляем через SignatureManager
                conn = self.signature_manager.signatures_db
                cursor = conn.cursor()
                
                for sig in signatures:
                    cursor.execute('''
                        INSERT OR REPLACE INTO signatures 
                        (name, type, pattern, hash, description, severity)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        sig.get("name"),
                        sig.get("type"),
                        sig.get("pattern"),
                        sig.get("hash"),
                        sig.get("description"),
                        sig.get("severity", "Medium")
                    ))
                
                conn.commit()
            
            # Обновляем движок если нужно
            engine_update = extract_dir / "engine_update"
            if engine_update.exists():
                self._update_engine(engine_update, manifest)
            
            # Очищаем временные файлы
            import shutil
            shutil.rmtree(extract_dir, ignore_errors=True)
            update_file.unlink(missing_ok=True)
            
            return True, "Обновление успешно применено"
            
        except Exception as e:
            return False, f"Ошибка применения обновления: {str(e)}"
    
    def _update_engine(self, engine_dir, manifest):
        """Обновление сканирующего движка"""
        try:
            # Резервное копирование текущего движка
            backup_dir = self.data_dir / "engine_backup"
            backup_dir.mkdir(exist_ok=True)
            
            # Копируем текущие файлы движка
            engine_files = [
                "scanner.py",
                "pe_analyzer.py",
                "sandbox.py"
            ]
            
            for file_name in engine_files:
                source_file = Path(__file__).parent / file_name
                if source_file.exists():
                    backup_file = backup_dir / f"{file_name}.backup"
                    import shutil
                    shutil.copy2(source_file, backup_file)
            
            # Копируем новые файлы
            for file_name in engine_files:
                new_file = engine_dir / file_name
                if new_file.exists():
                    target_file = Path(__file__).parent / file_name
                    shutil.copy2(new_file, target_file)
            
            # Обновляем версию движка
            if "engine_version" in manifest:
                self.update_info["engine_version"] = manifest["engine_version"]
            
            return True
            
        except Exception:
            # В случае ошибки восстанавливаем из бэкапа
            self._restore_engine_backup(backup_dir)
            return False

    def _restore_engine_backup(self, backup_dir):
        """Восстановление движка из бэкапа"""
        try:
            for backup_file in backup_dir.glob("*.backup"):
                original_name = backup_file.stem  # Убираем .backup
                original_file = Path(__file__).parent / original_name
                
                import shutil
                shutil.copy2(backup_file, original_file)
            
            return True
        except Exception:
            return False

    def _calculate_file_hash(self, file_path):
        """Вычисление MD5 хеша файла"""
        md5_hash = hashlib.md5()
        
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
        
        return md5_hash.hexdigest()

    def _compare_versions(self, version1, version2):
        """Сравнение версий"""
        def parse_version(version):
            parts = version.split('.')
            return [int(part) for part in parts]
        
        v1_parts = parse_version(version1)
        v2_parts = parse_version(version2)
        
        for v1, v2 in zip(v1_parts, v2_parts):
            if v1 > v2:
                return 1
            elif v1 < v2:
                return -1
        
        return 0
    
    def automatic_update_check(self):
        """Автоматическая проверка обновлений"""
        # Проверяем, нужно ли проверять обновления
        last_update = self.update_info.get("last_update")
        
        if last_update:
            try:
                last_update_date = datetime.fromisoformat(last_update)
                days_since_update = (datetime.now() - last_update_date).days
                
                # Проверяем раз в день
                if days_since_update < 1:
                    return
            except:
                pass
        
        # Проверяем обновления
        update_info = self.check_for_updates()
        
        if update_info.get("available", False):
            # Если критическое обновление - обновляем сразу
            if update_info.get("critical", False):
                self.update_all()
            else:
                # Иначе запоминаем что есть обновление
                self.update_info["update_available"] = update_info
                self._save_update_info()
    
    def get_update_status(self):
        """Получение статуса обновлений"""
        return {
            "last_update": self.update_info.get("last_update"),
            "signature_version": self.update_info.get("signature_version"),
            "engine_version": self.update_info.get("engine_version"),
            "update_available": self.update_info.get("update_available", {}),
            "update_attempts": self.update_info.get("update_attempts", 0)
        }
    
    def rollback_update(self, version):
        """Откат к предыдущей версии"""
        # TODO: Реализация отката обновлений
        pass
