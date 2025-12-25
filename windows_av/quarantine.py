"""
Менеджер карантина для WindowsAV
"""

import os
import json
from datetime import datetime
from pathlib import Path


class QuarantineManager:
    """Управление карантином зараженных файлов"""

    def __init__(self, data_dir):
        self.data_dir = Path(data_dir) / "quarantine"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Файл метаданных карантина
        self.metadata_file = self.data_dir / "metadata.json"
        self.metadata = self._load_metadata()

    def _load_metadata(self):
        """Загрузка метаданных карантина"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {"files": [], "version": "1.0"}

        # Создаем начальные метаданные
        metadata = {
            "files": [],
            "version": "1.0",
            "created": datetime.now().isoformat()
        }

        # Сохраняем
        self._save_metadata(metadata)
        return metadata

    def _save_metadata(self, metadata=None):
        """Сохранение метаданных карантина"""
        if metadata is None:
            metadata = self.metadata

        with open(self.metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)

    def get_quarantine_list(self):
        """Получение списка файлов в карантине"""
        files_list = []

        for file_info in self.metadata.get("files", []):
            # Убедимся что есть все необходимые поля
            file_info.setdefault("date", file_info.get("quarantine_date", "Неизвестно"))
            file_info.setdefault("original_path", "Неизвестный путь")
            file_info.setdefault("threat_name", "Неизвестная угроза")

            files_list.append({
                "id": file_info.get("id", ""),
                "original_path": file_info.get("original_path", ""),
                "threat_name": file_info.get("threat_name", ""),
                "date": file_info.get("date", ""),
                "file_size": file_info.get("file_size", 0),
                "quarantine_date": file_info.get("quarantine_date", ""),
                "original_path": file_info.get("original_path", "")
            })

        return files_list

    def quarantine_file(self, file_path, threat_name="Unknown"):
        """Помещение файла в карантин (заглушка)"""
        try:
            # Создаем запись о файле
            file_id = f"file_{len(self.metadata['files']) + 1}"

            file_info = {
                "id": file_id,
                "original_path": file_path,
                "threat_name": threat_name,
                "date": datetime.now().strftime("%d.%m.%Y %H:%M"),
                "quarantine_date": datetime.now().isoformat(),
                "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                "status": "quarantined"
            }

            # Добавляем в метаданные
            self.metadata["files"].append(file_info)
            self._save_metadata()

            return True, f"Файл {os.path.basename(file_path)} помещен в карантин"

        except Exception as e:
            return False, f"Ошибка: {str(e)}"

    def restore_file(self, file_path):
        """Восстановление файла из карантина (заглушка)"""
        try:
            # Ищем файл в метаданных
            for file_info in self.metadata["files"]:
                if file_info.get("original_path") == file_path:
                    file_info["status"] = "restored"
                    file_info["restore_date"] = datetime.now().isoformat()
                    self._save_metadata()
                    return True, f"Файл {os.path.basename(file_path)} восстановлен"

            return False, "Файл не найден в карантине"

        except Exception as e:
            return False, f"Ошибка: {str(e)}"

    def delete_quarantined(self, file_path):
        """Удаление файла из карантина (заглушка)"""
        try:
            # Ищем и удаляем файл из метаданных
            original_files = self.metadata["files"]
            self.metadata["files"] = [
                f for f in original_files
                if f.get("original_path") != file_path
            ]

            self._save_metadata()
            return True, "Файл удален из карантина"

        except Exception as e:
            return False, f"Ошибка: {str(e)}"

    def clear_quarantine(self):
        """Очистка всего карантина"""
        try:
            self.metadata["files"] = []
            self._save_metadata()
            return True, "Карантин очищен"
        except Exception as e:
            return False, f"Ошибка: {str(e)}"
