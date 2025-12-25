"""
Менеджер сигнатур и баз данных WindowsAV
"""

import sqlite3
from pathlib import Path
from datetime import datetime
import requests


class SignatureManager:
    """Управление сигнатурами и базами данных"""
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.signatures_db = self.data_dir / "signatures.db"
        self.cache_db = self.data_dir / "cache.db"

        self._init_databases()

        self._load_default_signatures()
    
    def _init_databases(self):
        """Инициализация баз данных"""
        conn = sqlite3.connect(self.signatures_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                pattern TEXT,
                hash TEXT,
                description TEXT,
                severity TEXT,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                hash TEXT,
                reason TEXT,
                added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_cache (
                path TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                last_scan TIMESTAMP,
                threat_level TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_default_signatures(self):
        """Загрузка сигнатур по умолчанию"""
        default_signatures = [
            # EICAR test signature
            {
                "name": "EICAR Test File",
                "type": "content",
                "pattern": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                "description": "EICAR test file signature",
                "severity": "Low"
            },
            # Common malware patterns
            {
                "name": "Meterpreter Stager",
                "type": "bytes",
                "pattern": "fc4883e4f0e8cc000000",
                "description": "Metasploit meterpreter stager",
                "severity": "High"
            },
            {
                "name": "Shellcode XOR Decoder",
                "type": "bytes",
                "pattern": "31c931db31d231c0b0",
                "description": "Common shellcode XOR decoder",
                "severity": "Medium"
            },
            # Ransomware indicators
            {
                "name": "Ransomware Note",
                "type": "content",
                "pattern": "Your files have been encrypted",
                "description": "Ransomware ransom note",
                "severity": "Critical"
            },
            # Common hack tools
            {
                "name": "Mimikatz Pattern",
                "type": "content",
                "pattern": "mimikatz",
                "description": "Mimikatz credential dumping tool",
                "severity": "High"
            }
        ]
        
        conn = sqlite3.connect(self.signatures_db)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM signatures")
        count = cursor.fetchone()[0]
        
        if count == 0:
            for sig in default_signatures:
                cursor.execute('''
                    INSERT INTO signatures (name, type, pattern, description, severity)
                    VALUES (?, ?, ?, ?, ?)
                ''', (sig["name"], sig["type"], sig.get("pattern"), 
                      sig["description"], sig["severity"]))
        
        conn.commit()
        conn.close()
    
    def check_hash(self, file_hash):
        """Проверка хеша файла в базе"""
        if not file_hash:
            return None
        
        conn = sqlite3.connect(self.signatures_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT name, type, description, severity 
            FROM signatures 
            WHERE hash = ? OR pattern = ?
        ''', (file_hash, file_hash))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                "name": result[0],
                "type": result[1],
                "description": result[2],
                "severity": result[3]
            }
        
        return None
    
    def check_content(self, file_data):
        """Проверка содержимого файла"""
        conn = sqlite3.connect(self.signatures_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT name, type, pattern, description, severity 
            FROM signatures 
            WHERE type IN ('content', 'bytes')
        ''')
        
        signatures = cursor.fetchall()
        conn.close()
        
        file_text = file_data.decode('utf-8', errors='ignore').lower()
        
        for sig in signatures:
            name, sig_type, pattern, description, severity = sig
            
            if sig_type == "content" and pattern:
                if pattern.lower() in file_text:
                    return {
                        "name": name,
                        "type": sig_type,
                        "description": description,
                        "severity": severity
                    }
            
            elif sig_type == "bytes" and pattern:
                try:
                    pattern_bytes = bytes.fromhex(pattern)
                    if pattern_bytes in file_data:
                        return {
                            "name": name,
                            "type": sig_type,
                            "description": description,
                            "severity": severity
                        }
                except:
                    continue
        
        return None
    
    def add_signature(self, name, sig_type, pattern=None, hash_value=None, 
                     description="", severity="Medium"):
        """Добавление новой сигнатуры"""
        conn = sqlite3.connect(self.signatures_db)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO signatures (name, type, pattern, hash, description, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, sig_type, pattern, hash_value, description, severity))
            
            conn.commit()
            return True, "Сигнатура добавлена"
            
        except Exception as e:
            return False, f"Ошибка: {str(e)}"
        
        finally:
            conn.close()
    
    def remove_signature(self, signature_id):
        """Удаление сигнатуры"""
        conn = sqlite3.connect(self.signatures_db)
        cursor = conn.cursor()
        
        try:
            cursor.execute("DELETE FROM signatures WHERE id = ?", (signature_id,))
            conn.commit()
            return True, "Сигнатура удалена"
            
        except Exception as e:
            return False, f"Ошибка: {str(e)}"
        
        finally:
            conn.close()
    
    def get_all_signatures(self):
        """Получение всех сигнатур"""
        conn = sqlite3.connect(self.signatures_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, name, type, pattern, hash, description, severity, created
            FROM signatures
            ORDER BY created DESC
        ''')
        
        signatures = []
        for row in cursor.fetchall():
            signatures.append({
                "id": row[0],
                "name": row[1],
                "type": row[2],
                "pattern": row[3],
                "hash": row[4],
                "description": row[5],
                "severity": row[6],
                "created": row[7]
            })
        
        conn.close()
        return signatures
    
    def update_from_server(self, server_url):
        """Обновление баз с сервера"""
        try:
            response = requests.get(f"{server_url}/signatures.json", timeout=10)
            
            if response.status_code == 200:
                signatures = response.json()
                
                conn = sqlite3.connect(self.signatures_db)
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
                conn.close()
                
                return True, f"Обновлено {len(signatures)} сигнатур"
            else:
                return False, f"Ошибка сервера: {response.status_code}"
                
        except Exception as e:
            return False, f"Ошибка соединения: {str(e)}"
    
    def add_to_whitelist(self, file_path, reason=""):
        """Добавление файла в белый список"""
        conn = sqlite3.connect(self.signatures_db)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO whitelist (path, reason)
                VALUES (?, ?)
            ''', (file_path, reason))
            
            conn.commit()
            return True, "Файл добавлен в белый список"
            
        except Exception as e:
            return False, f"Ошибка: {str(e)}"
        
        finally:
            conn.close()
    
    def is_whitelisted(self, file_path):
        """Проверка, находится ли файл в белом списке"""
        conn = sqlite3.connect(self.signatures_db)
        cursor = conn.cursor()
        
        cursor.execute("SELECT 1 FROM whitelist WHERE path = ?", (file_path,))
        result = cursor.fetchone() is not None
        
        conn.close()
        return result
    
    def update_cache(self, file_path, file_hash, threat_level=None):
        """Обновление кэша сканирования"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO scan_cache 
                (path, hash, last_scan, threat_level)
                VALUES (?, ?, datetime('now'), ?)
            ''', (file_path, file_hash, threat_level))
            
            conn.commit()
            
        finally:
            conn.close()
    
    def get_cached_result(self, file_path, file_hash):
        """Получение результата из кэша"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT threat_level FROM scan_cache 
            WHERE path = ? AND hash = ?
        ''', (file_path, file_hash))
        
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else None
    
    def get_statistics(self):
        """Получение статистики баз"""
        conn = sqlite3.connect(self.signatures_db)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM signatures")
        signature_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM whitelist")
        whitelist_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "signatures": signature_count,
            "whitelist": whitelist_count,
            "last_update": datetime.now().strftime("%d.%m.%Y %H:%M")
        }
