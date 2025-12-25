import json
import os
from pathlib import Path


def get_user_data_dir():
    """Получение директории данных пользователя"""
    app_data = os.environ.get("APPDATA", os.path.join(os.environ["USERPROFILE"], "AppData\\Roaming"))
    data_dir = Path(app_data) / "WindowsAV"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_program_files_dir():
    """Получение директории Program Files"""
    program_files = os.environ.get("PROGRAMFILES", "C:\\Program Files")
    return Path(program_files) / "WindowsAV"


CONFIG = {
    "app_name": "WindowsAV",
    "version": "1.0.0",
    "company": "Windows Security Team",
    
    # Пути
    "data_dir": str(get_user_data_dir()),
    "program_dir": str(get_program_files_dir()),
    "log_dir": str(get_user_data_dir() / "logs"),
    "quarantine_dir": str(get_user_data_dir() / "quarantine"),
    "temp_dir": str(Path(os.environ.get("TEMP", "C:\\Windows\\Temp")) / "WindowsAV"),
    
    # Настройки сканирования
    "scan": {
        "max_file_size": 100 * 1024 * 1024,  # 100MB
        "scan_timeout": 300,  # 5 минут
        "quick_scan_paths": [
            "$SYSTEMROOT",
            "$PROGRAMFILES",
            "$PROGRAMFILES(X86)",
            "$APPDATA",
            "$LOCALAPPDATA",
            "$TEMP"
        ],
        "excluded_extensions": [
            ".log", ".tmp", ".cache", ".db", ".db-journal",
            ".lock", ".pid", ".sock"
        ],
        "excluded_paths": [
            "$SYSTEMROOT\\Temp",
            "$SYSTEMROOT\\Logs",
            "$APPDATA\\Microsoft\\Windows\\Recent"
        ]
    },
    
    # Настройки обновления
    "update": {
        "check_interval": 86400,  # 24 часа
        "auto_update": True,
        "update_servers": [
            "https://windows-av-updates.example.com",
            "https://backup-updates.example.com"
        ],
        "proxy": None
    },
    
    # Настройки защиты в реальном времени
    "realtime_protection": {
        "enabled": True,
        "monitor_file_changes": True,
        "monitor_processes": True,
        "monitor_registry": False,
        "scan_on_execute": True,
        "scan_on_write": True
    },
    
    # Настройки карантина
    "quarantine": {
        "max_size": 1024 * 1024 * 1024,  # 1GB
        "auto_delete_after_days": 30,
        "encryption_enabled": True
    },
    
    # Настройки интерфейса
    "ui": {
        "language": "ru",
        "theme": "default",
        "show_notifications": True,
        "minimize_to_tray": True,
        "start_minimized": False
    },
    
    # Настройки отчетов
    "reports": {
        "keep_history_days": 7,
        "max_report_size": 50 * 1024 * 1024,  # 50MB
        "auto_generate_reports": True
    },
    
    # Настройки безопасности
    "security": {
        "require_password_for_settings": False,
        "password_hash": None,
        "admin_rights_required": True
    }
}


class ConfigManager:
    """Менеджер конфигурации"""
    
    def __init__(self, config_file=None):
        if config_file is None:
            config_file = get_user_data_dir() / "config.json"
        
        self.config_file = Path(config_file)
        self.config = CONFIG.copy()

        self.load()
    
    def load(self):
        """Загрузка конфигурации из файла"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                
                # Рекурсивное обновление конфигурации
                self._update_dict(self.config, saved_config)
        except Exception:
            pass
    
    def save(self):
        """Сохранение конфигурации в файл"""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception:
            return False
    
    def get(self, key, default=None):
        """Получение значения конфигурации"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key, value):
        """Установка значения конфигурации"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        
        # Сохраняем изменения
        self.save()
    
    def reset(self, section=None):
        """Сброс конфигурации к значениям по умолчанию"""
        if section:
            if section in CONFIG:
                self.config[section] = CONFIG[section].copy()
        else:
            self.config = CONFIG.copy()
        
        self.save()
    
    def _update_dict(self, target, source):
        """Рекурсивное обновление словаря"""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._update_dict(target[key], value)
            else:
                target[key] = value
    
    def expand_path(self, path):
        """Раскрытие переменных в пути"""
        if not path:
            return path
        
        # Заменяем переменные окружения
        path = os.path.expandvars(path)
        
        # Заменяем специфичные переменные WindowsAV
        replacements = {
            "$DATA_DIR": self.get("data_dir"),
            "$PROGRAM_DIR": self.get("program_dir"),
            "$LOG_DIR": self.get("log_dir"),
            "$QUARANTINE_DIR": self.get("quarantine_dir"),
            "$TEMP_DIR": self.get("temp_dir")
        }
        
        for var, value in replacements.items():
            if value:
                path = path.replace(var, value)
        
        return Path(path)
    
    def get_scan_paths(self, scan_type="quick"):
        """Получение путей для сканирования"""
        if scan_type == "quick":
            path_templates = self.get("scan.quick_scan_paths", [])
        else:
            # Для полного сканирования сканируем все диски
            import win32api
            drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
            return [Path(drive) for drive in drives]
        
        paths = []
        for template in path_templates:
            path = self.expand_path(template)
            if path.exists():
                paths.append(path)
        
        return paths
    
    def is_excluded(self, file_path):
        """Проверка, исключен ли файл из сканирования"""
        file_path = Path(file_path)
        
        # Проверка по расширению
        excluded_exts = self.get("scan.excluded_extensions", [])
        if file_path.suffix.lower() in excluded_exts:
            return True
        
        # Проверка по пути
        excluded_paths = self.get("scan.excluded_paths", [])
        for excluded_template in excluded_paths:
            excluded_path = self.expand_path(excluded_template)
            if str(file_path).startswith(str(excluded_path)):
                return True
        
        return False

# Глобальный экземпляр менеджера конфигурации
config_manager = ConfigManager()

# Функции для удобства
def get_config():
    """Получение глобальной конфигурации"""
    return config_manager.config

def get_setting(key, default=None):
    """Получение настройки"""
    return config_manager.get(key, default)

def set_setting(key, value):
    """Установка настройки"""
    return config_manager.set(key, value)

def save_config():
    """Сохранение конфигурации"""
    return config_manager.save()

def reset_config(section=None):
    """Сброс конфигурации"""
    return config_manager.reset(section)