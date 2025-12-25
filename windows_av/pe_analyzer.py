"""
Углубленный анализатор PE файлов для Windows
"""

import pefile
from datetime import datetime

class PEAnalyzer:
    """Анализатор PE файлов Windows"""
    
    def __init__(self):
        self.suspicious_sections = {
            ".text", ".data", ".rdata", ".idata", ".edata", 
            ".pdata", ".rsrc", ".reloc", ".bss", ".tls"
        }
        
        self.suspicious_imports = {
            # Process Injection
            "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
            "ReadProcessMemory", "OpenProcess", "QueueUserAPC",
            
            # Code Execution
            "CreateProcess", "ShellExecute", "WinExec", "system",
            "_wsystem", "popen", "ShellExecuteEx",
            
            # Network
            "socket", "connect", "send", "recv", "bind", "listen",
            "WSAStartup", "WSASocket", "URLDownloadToFile", "InternetOpenUrl",
            "HttpOpenRequest", "InternetConnect",
            
            # Registry
            "RegSetValue", "RegCreateKey", "RegDeleteKey", "RegOpenKey",
            
            # Services
            "CreateService", "StartService", "OpenSCManager", "ControlService",
            
            # Hooking
            "SetWindowsHook", "SetWinEventHook", "SetWindowsHookEx",
            
            # Memory
            "VirtualProtect", "VirtualAlloc", "VirtualFree", "HeapCreate",
            
            # DLL Injection
            "LoadLibrary", "GetProcAddress", "FreeLibrary", "LoadLibraryEx"
        }
        
        self.suspicious_dlls = {
            "ws2_32.dll", "wininet.dll", "urlmon.dll", "ole32.dll",
            "oleaut32.dll", "shell32.dll", "advapi32.dll", "ntdll.dll",
            "kernel32.dll", "user32.dll", "gdi32.dll"
        }
    
    def analyze(self, file_path, file_data=None):
        """Анализ PE файла"""
        try:
            if file_data:
                pe = pefile.PE(data=file_data, fast_load=True)
            else:
                pe = pefile.PE(file_path, fast_load=True)
            
            analysis_result = {
                "is_pe": True,
                "suspicious_indicators": [],
                "warnings": [],
                "info": {},
                "score": 0
            }

            # Базовая информация
            analysis_result["info"] = self._get_basic_info(pe)
            
            # Анализ секций
            section_indicators = self._analyze_sections(pe)
            analysis_result["suspicious_indicators"].extend(section_indicators)
            
            # Анализ импортов
            import_indicators = self._analyze_imports(pe)
            analysis_result["suspicious_indicators"].extend(import_indicators)
            
            # Анализ экспортов
            export_indicators = self._analyze_exports(pe)
            analysis_result["suspicious_indicators"].extend(export_indicators)
            
            # Анализ ресурсов
            resource_indicators = self._analyze_resources(pe)
            analysis_result["suspicious_indicators"].extend(resource_indicators)
            
            # Анализ заголовков
            header_indicators = self._analyze_headers(pe)
            analysis_result["suspicious_indicators"].extend(header_indicators)
            
            # Расчет общего скора
            analysis_result["score"] = self._calculate_score(analysis_result)
            
            # Определение уровня угрозы
            analysis_result["threat_level"] = self._determine_threat_level(analysis_result["score"])
            
            return analysis_result
            
        except Exception as e:
            return {
                "is_pe": False,
                "error": str(e),
                "suspicious_indicators": [],
                "warnings": [],
                "info": {},
                "score": 0,
                "threat_level": "Unknown"
            }
    
    def _get_basic_info(self, pe):
        """Получение базовой информации о PE файле"""
        info = {}
        
        try:
            # Архитектура
            if pe.FILE_HEADER.Machine == 0x014c:
                info["architecture"] = "x86"
            elif pe.FILE_HEADER.Machine == 0x8664:
                info["architecture"] = "x64"
            else:
                info["architecture"] = f"0x{pe.FILE_HEADER.Machine:04x}"
            
            # Тип файла
            characteristics = pe.FILE_HEADER.Characteristics
            if characteristics & 0x2000:
                info["type"] = "DLL"
            elif characteristics & 0x0002:
                info["type"] = "EXE"
            else:
                info["type"] = "Unknown"
            
            # Время компиляции
            compile_time = pe.FILE_HEADER.TimeDateStamp
            if compile_time:
                info["compile_time"] = datetime.fromtimestamp(compile_time).strftime("%d.%m.%Y %H:%M")
            else:
                info["compile_time"] = "Unknown"
            
            # Количество секций
            info["num_sections"] = pe.FILE_HEADER.NumberOfSections
            
            # Характеристики
            info["characteristics"] = hex(characteristics)
            
            # Размеры
            if hasattr(pe, "OPTIONAL_HEADER"):
                info["image_size"] = pe.OPTIONAL_HEADER.SizeOfImage
                info["code_size"] = pe.OPTIONAL_HEADER.SizeOfCode
                info["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            
        except Exception:
            pass
        
        return info
    
    def _analyze_sections(self, pe):
        """Анализ секций PE файла"""
        indicators = []
        
        for section in pe.sections:
            try:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                
                # Проверка имени секции
                if section_name not in self.suspicious_sections:
                    indicators.append(f"Нестандартное имя секции: {section_name}")
                
                # Проверка атрибутов RWX
                characteristics = section.Characteristics
                
                is_readable = characteristics & 0x40000000
                is_writable = characteristics & 0x80000000
                is_executable = characteristics & 0x20000000
                
                if is_readable and is_writable and is_executable:
                    indicators.append(f"Секция {section_name} имеет атрибуты RWX (чтение/запись/выполнение)")
                elif is_writable and is_executable:
                    indicators.append(f"Секция {section_name} имеет атрибуты WX (запись/выполнение)")
                
                # Проверка размера
                if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                    indicators.append(f"Секция {section_name} имеет нулевой размер на диске, но ненулевой в памяти")
                
                # Проверка энтропии
                entropy = self._calculate_entropy(section.get_data())
                if entropy > 7.0:
                    indicators.append(f"Высокая энтропия в секции {section_name}: {entropy:.2f}")
                
            except Exception:
                continue
        
        return indicators
    
    def _analyze_imports(self, pe):
        """Анализ импортов"""
        indicators = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    
                    # Проверка подозрительных DLL
                    if dll_name in self.suspicious_dlls:
                        indicators.append(f"Использует системную DLL: {dll_name}")
                    
                    # Проверка импортов
                    for imp in entry.imports:
                        if imp.name:
                            import_name = imp.name.decode('utf-8', errors='ignore')
                            
                            if import_name in self.suspicious_imports:
                                indicators.append(f"Подозрительный импорт: {import_name} из {dll_name}")
                            
                            # Анти-отладка
                            if any(term in import_name.lower() for term in ['debug', 'isdebug', 'ntquery', 'rdtsc']):
                                indicators.append(f"Анти-отладочный импорт: {import_name}")
                            
                            # Сокрытие
                            if any(term in import_name.lower() for term in ['hide', 'hidden', 'stealth']):
                                indicators.append(f"Импорт для сокрытия: {import_name}")
                
                except Exception:
                    continue
        
        return indicators
    
    def _analyze_exports(self, pe):
        """Анализ экспортов"""
        indicators = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = pe.DIRECTORY_ENTRY_EXPORT
            
            try:
                if exports.symbols:
                    for exp in exports.symbols:
                        if exp.name:
                            export_name = exp.name.decode('utf-8', errors='ignore')
                            
                            # Проверка подозрительных имен экспортов
                            suspicious_exports = {'start', 'main', 'run', 'execute', 'install', 'service'}
                            if export_name.lower() in suspicious_exports:
                                indicators.append(f"Подозрительный экспорт: {export_name}")
            except Exception:
                pass
        
        return indicators
    
    def _analyze_resources(self, pe):
        """Анализ ресурсов"""
        indicators = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            try:
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.name:
                        res_name = str(resource_type.name)
                        
                        # Проверка на встроенные исполняемые файлы
                        if any(term in res_name.upper() for term in ['EXE', 'DLL', 'BIN', 'CODE']):
                            indicators.append(f"Подозрительный ресурс: {res_name}")
                        
                        # Проверка на иконки (иногда маскируются)
                        if 'ICON' in res_name.upper() and resource_type.struct.DataSize > 100000:
                            indicators.append(f"Большой ресурс иконки: {res_name} ({resource_type.struct.DataSize} байт)")
                
                # Проверка на наличие манифеста
                if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                        if entry.id == 24:  # RT_MANIFEST
                            indicators.append("Наличие манифеста (возможность повышения привилегий)")
                            break
                            
            except Exception:
                pass
        
        return indicators
    
    def _analyze_headers(self, pe):
        """Анализ заголовков"""
        indicators = []
        
        try:
            # Проверка размера заголовков
            if hasattr(pe, "OPTIONAL_HEADER"):
                size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
                if size_of_headers > 4096:
                    indicators.append(f"Большой размер заголовков: {size_of_headers} байт")
                
                # Проверка точки входа
                entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                if entry_point < pe.OPTIONAL_HEADER.SizeOfHeaders:
                    indicators.append(f"Точка входа внутри заголовков (возможный упаковщик)")
                
                # Проверка контрольной суммы
                checksum = pe.OPTIONAL_HEADER.CheckSum
                calculated_checksum = pe.generate_checksum()
                
                if checksum != 0 and checksum != calculated_checksum:
                    indicators.append("Неверная контрольная сумма (возможно модифицирован)")
            
            # Проверка количества секций
            num_sections = pe.FILE_HEADER.NumberOfSections
            if num_sections > 20:
                indicators.append(f"Большое количество секций: {num_sections}")
            elif num_sections < 3:
                indicators.append(f"Малое количество секций: {num_sections}")
            
            # Проверка времени компиляции
            compile_time = pe.FILE_HEADER.TimeDateStamp
            current_time = datetime.now().timestamp()
            
            if compile_time == 0:
                indicators.append("Время компиляции равно нулю")
            elif compile_time > current_time:
                indicators.append(f"Время компиляции в будущем: {datetime.fromtimestamp(compile_time)}")
            elif compile_time < 631152000:  # 1990 год
                indicators.append(f"Очень старое время компиляции: {datetime.fromtimestamp(compile_time)}")
            
        except Exception:
            pass
        
        return indicators
    
    def _calculate_entropy(self, data):
        """Расчет энтропии данных"""
        if not data:
            return 0.0
        
        import math
        
        # Подсчет частоты байтов
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        # Расчет энтропии
        entropy = 0.0
        data_len = len(data)
        
        for count in frequency.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_score(self, analysis_result):
        """Расчет общего скора угрозы"""
        score = 0
        
        indicators = analysis_result["suspicious_indicators"]
        
        # Веса различных индикаторов
        weights = {
            "RWX": 10,
            "WX": 8,
            "нестандартное имя секции": 3,
            "высокая энтропия": 5,
            "подозрительный импорт": 4,
            "анти-отладочный": 6,
            "подозрительный экспорт": 3,
            "подозрительный ресурс": 4,
            "время компиляции": 2,
            "контрольная сумма": 7,
            "точка входа": 6
        }
        
        for indicator in indicators:
            for key, weight in weights.items():
                if key in indicator.lower():
                    score += weight
                    break
        
        return min(score, 100)
    
    def _determine_threat_level(self, score):
        """Определение уровня угрозы по скору"""
        if score >= 40:
            return "Critical"
        elif score >= 25:
            return "High"
        elif score >= 15:
            return "Medium"
        elif score >= 5:
            return "Low"
        else:
            return "Clean"
    
    def detect_packer(self, pe):
        """Определение упаковщика/протектора"""
        packer_signatures = {
            b"UPX": "UPX",
            b"ASPack": "ASPack",
            b"FSG": "FSG",
            b"PECompact": "PECompact",
            b"Petite": "Petite",
            b"MEW": "MEW",
            b"UPack": "UPack",
            b"NsPack": "NsPack",
            b"WinUpack": "WinUpack",
            b"Themida": "Themida",
            b"VMProtect": "VMProtect",
            b"Armadillo": "Armadillo",
            b"Obsidium": "Obsidium",
            b"Enigma": "Enigma"
        }
        
        # Проверка по секциям
        for section in pe.sections:
            section_data = section.get_data()
            for signature, name in packer_signatures.items():
                if signature in section_data:
                    return name
        
        # Проверка по ресурсам
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            try:
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'data'):
                            resource_data = pe.get_data(
                                resource_id.data.struct.OffsetToData,
                                resource_id.data.struct.Size
                            )
                            for signature, name in packer_signatures.items():
                                if signature in resource_data:
                                    return name
            except:
                pass
        
        return None
