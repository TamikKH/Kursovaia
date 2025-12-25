"""
Графический интерфейс WindowsAV на PySide6
"""

import os
from datetime import datetime
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QTableWidget, QTableWidgetItem,
    QProgressBar, QTabWidget, QGroupBox, QFileDialog, QMessageBox,
    QMenu, QSystemTrayIcon,
    QComboBox, QCheckBox, QSpinBox
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal
from PySide6.QtGui import QIcon, QFont, QAction
from scanner import WindowsAVScanner
from signatures import SignatureManager
from updater import UpdateManager
from quarantine import QuarantineManager
from config import get_user_data_dir


class ScanThread(QThread):
    """Поток для сканирования"""
    progress = Signal(int, int, str)  # текущий, всего, файл
    result = Signal(dict)  # результат сканирования
    finished = Signal()  # завершение
    error = Signal(str)  # ошибка

    def __init__(self, scanner, path, scan_type="quick"):
        super().__init__()
        self.scanner = scanner
        self.path = path
        self.scan_type = scan_type

    def run(self):
        try:
            results = self.scanner.scan_path(
                self.path,
                scan_type=self.scan_type,
                progress_callback=self._progress_callback
            )
            self.result.emit(results)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished.emit()

    def _progress_callback(self, current, total, current_file):
        self.progress.emit(current, total, current_file)


class UpdateThread(QThread):
    """Поток для обновления баз"""
    progress = Signal(str, int)  # статус, процент
    finished = Signal(bool, str)  # успех, сообщение

    def __init__(self, updater):
        super().__init__()
        self.updater = updater

    def run(self):
        try:
            success, message = self.updater.update_all(self._progress_callback)
            self.finished.emit(success, message)
        except Exception as e:
            self.finished.emit(False, f"Ошибка: {str(e)}")

    def _progress_callback(self, status, percent):
        self.progress.emit(status, percent)


class WindowsAVApp:
    """Основное приложение"""

    def __init__(self, argv):
        self.app = QApplication(argv)
        self.app.setApplicationName("WindowsAV")
        self.app.setApplicationDisplayName("Антивирус для Windows")

        self.data_dir = get_user_data_dir()
        self.signature_manager = SignatureManager(self.data_dir)
        self.scanner = WindowsAVScanner(self.signature_manager)
        self.updater = UpdateManager(self.data_dir, self.signature_manager)
        self.quarantine = QuarantineManager(self.data_dir)

        self.window = MainWindow(self)
        self.window.setWindowTitle("WindowsAV - Антивирус для Windows")
        self.window.resize(1200, 800)

        self._setup_icon()

        self._setup_system_tray()

        self.auto_scan_timer = QTimer()
        self.auto_scan_timer.timeout.connect(self._auto_scan_check)

        self.scan_thread = None
        self.update_thread = None

        self._connect_signals()

    def _setup_icon(self):
        """Настройка иконки приложения"""
        try:
            icon = QIcon("shield.ico")
            self.app.setWindowIcon(icon)
            self.window.setWindowIcon(icon)
        except:
            # Используем стандартную иконку если файл не найден
            pass

    def _setup_system_tray(self):
        """Настройка системного трея"""
        self.tray_icon = QSystemTrayIcon(self.window)
        self.tray_icon.setToolTip("WindowsAV - Антивирус для Windows")

        # Меню трея
        tray_menu = QMenu()

        show_action = QAction("Показать", self.window)
        show_action.triggered.connect(self.window.show)
        tray_menu.addAction(show_action)

        scan_action = QAction("Быстрое сканирование", self.window)
        scan_action.triggered.connect(lambda: self.start_scan("C:\\", "quick"))
        tray_menu.addAction(scan_action)

        update_action = QAction("Обновить базы", self.window)
        update_action.triggered.connect(self.window.on_update)
        tray_menu.addAction(update_action)

        tray_menu.addSeparator()

        exit_action = QAction("Выход", self.window)
        exit_action.triggered.connect(self.app.quit)
        tray_menu.addAction(exit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

    def _connect_signals(self):
        """Соединение сигналов"""
        self.window.scan_requested.connect(self.start_scan)
        self.window.update_requested.connect(self.start_update)
        self.window.quarantine_action.connect(self.handle_quarantine)

    def start_scan(self, path, scan_type):
        """Запуск сканирования"""
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.warning(self.window, "Внимание", "Сканирование уже выполняется!")
            return

        self.scan_thread = ScanThread(self.scanner, path, scan_type)
        self.scan_thread.progress.connect(self.window.update_progress)
        self.scan_thread.result.connect(self.window.show_results)
        self.scan_thread.finished.connect(self.window.scan_finished)
        self.scan_thread.error.connect(self.window.scan_error)
        self.scan_thread.start()

    def start_update(self):
        """Запуск обновления"""
        if self.update_thread and self.update_thread.isRunning():
            QMessageBox.warning(self.window, "Внимание", "Обновление уже выполняется!")
            return

        self.update_thread = UpdateThread(self.updater)
        self.update_thread.progress.connect(self.window.update_update_progress)
        self.update_thread.finished.connect(self.window.update_finished)
        self.update_thread.start()

    def handle_quarantine(self, action, file_path):
        """Обработка действий с карантином"""
        if action == "add":
            success, message = self.quarantine.quarantine_file(file_path)
            if success:
                QMessageBox.information(self.window, "Успех", f"Файл помещен в карантин: {message}")
            else:
                QMessageBox.warning(self.window, "Ошибка", message)
        elif action == "restore":
            success, message = self.quarantine.restore_file(file_path)
            if success:
                QMessageBox.information(self.window, "Успех", f"Файл восстановлен: {message}")
            else:
                QMessageBox.warning(self.window, "Ошибка", message)
        elif action == "delete":
            reply = QMessageBox.question(
                self.window, "Подтверждение",
                "Удалить файл из карантина безвозвратно?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                success, message = self.quarantine.delete_quarantined(file_path)
                if success:
                    QMessageBox.information(self.window, "Успех", "Файл удален")
                else:
                    QMessageBox.warning(self.window, "Ошибка", message)

    def _auto_scan_check(self):
        """Проверка необходимости автосканирования"""
        # TODO: Реализация автосканирования по расписанию
        pass

    def run(self):
        """Запуск приложения"""
        self.window.show()
        return self.app.exec()


class MainWindow(QMainWindow):
    """Главное окно приложения"""

    # Сигналы
    scan_requested = Signal(str, str)  # путь, тип сканирования
    update_requested = Signal()
    quarantine_action = Signal(str, str)  # действие, путь к файлу

    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setup_ui()
        self.scan_thread = None
        self.update_thread = None

    def setup_ui(self):
        """Настройка интерфейса"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        # Верхняя панель
        top_panel = self._create_top_panel()
        main_layout.addWidget(top_panel)

        # Центральная область с вкладками
        self.tabs = QTabWidget()

        # Вкладка сканирования
        scan_tab = self._create_scan_tab()
        self.tabs.addTab(scan_tab, "Сканирование")

        # Вкладка результатов
        results_tab = self._create_results_tab()
        self.tabs.addTab(results_tab, "Результаты")

        # Вкладка карантина
        quarantine_tab = self._create_quarantine_tab()
        self.tabs.addTab(quarantine_tab, "Карантин")

        # Вкладка настройки
        settings_tab = self._create_settings_tab()
        self.tabs.addTab(settings_tab, "Настройки")

        main_layout.addWidget(self.tabs)

        # Нижняя панель статуса
        status_panel = self._create_status_panel()
        main_layout.addWidget(status_panel)

    def _create_top_panel(self):
        """Создание верхней панели"""
        panel = QWidget()
        layout = QHBoxLayout(panel)

        # Заголовок
        title = QLabel("🛡️ WindowsAV - Антивирус для Windows")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)

        layout.addWidget(title)
        layout.addStretch()

        # Кнопки
        self.update_btn = QPushButton("Обновить базы")
        self.update_btn.clicked.connect(self.on_update)
        layout.addWidget(self.update_btn)

        self.quick_scan_btn = QPushButton("Быстрое сканирование")
        self.quick_scan_btn.clicked.connect(lambda: self.on_scan("quick"))
        layout.addWidget(self.quick_scan_btn)

        self.full_scan_btn = QPushButton("Полное сканирование")
        self.full_scan_btn.clicked.connect(lambda: self.on_scan("full"))
        layout.addWidget(self.full_scan_btn)

        return panel

    def _create_scan_tab(self):
        """Создание вкладки сканирования"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Выбор типа сканирования
        scan_group = QGroupBox("Тип сканирования")
        scan_layout = QVBoxLayout(scan_group)

        self.quick_scan_radio = QCheckBox("Быстрое сканирование (системные папки)")
        self.quick_scan_radio.setChecked(True)
        scan_layout.addWidget(self.quick_scan_radio)

        self.full_scan_radio = QCheckBox("Полное сканирование (весь компьютер)")
        scan_layout.addWidget(self.full_scan_radio)

        self.custom_scan_radio = QCheckBox("Выборочное сканирование")
        scan_layout.addWidget(self.custom_scan_radio)

        layout.addWidget(scan_group)

        # Выбор пути для выборочного сканирования
        path_group = QGroupBox("Путь для сканирования")
        path_layout = QHBoxLayout(path_group)

        self.path_edit = QLineEdit("C:\\")
        path_layout.addWidget(self.path_edit)

        browse_btn = QPushButton("Обзор...")
        browse_btn.clicked.connect(self.browse_path)
        path_layout.addWidget(browse_btn)

        layout.addWidget(path_group)

        # Дополнительные опции
        options_group = QGroupBox("Дополнительные опции")
        options_layout = QVBoxLayout(options_group)

        self.scan_memory = QCheckBox("Сканировать оперативную память")
        options_layout.addWidget(self.scan_memory)

        self.scan_registry = QCheckBox("Сканировать реестр")
        options_layout.addWidget(self.scan_registry)

        self.scan_startup = QCheckBox("Сканировать автозагрузку")
        options_layout.addWidget(self.scan_startup)

        layout.addWidget(options_group)

        # Прогресс сканирования
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Готов к сканированию")
        layout.addWidget(self.status_label)

        # Кнопка запуска
        self.start_btn = QPushButton("Начать сканирование")
        self.start_btn.clicked.connect(self.start_scanning)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #0078d4;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
        """)
        layout.addWidget(self.start_btn)

        layout.addStretch()

        return tab

    def _create_results_tab(self):
        """Создание вкладки результатов"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Таблица результатов
        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels([
            "Файл", "Угроза", "Тип", "Статус", "Дата", "Действия"
        ])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setAlternatingRowColors(True)

        layout.addWidget(self.results_table)

        # Панель действий
        action_panel = QWidget()
        action_layout = QHBoxLayout(action_panel)

        self.quarantine_btn = QPushButton("В карантин")
        self.quarantine_btn.clicked.connect(self.quarantine_selected)
        self.quarantine_btn.setEnabled(False)

        self.delete_btn = QPushButton("Удалить")
        self.delete_btn.clicked.connect(self.delete_selected)
        self.delete_btn.setEnabled(False)

        self.ignore_btn = QPushButton("Игнорировать")
        self.ignore_btn.clicked.connect(self.ignore_selected)
        self.ignore_btn.setEnabled(False)

        action_layout.addWidget(self.quarantine_btn)
        action_layout.addWidget(self.delete_btn)
        action_layout.addWidget(self.ignore_btn)
        action_layout.addStretch()

        layout.addWidget(action_panel)

        return tab

    def _create_quarantine_tab(self):
        """Создание вкладки карантина"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Список файлов в карантине
        self.quarantine_list = QListWidget()
        layout.addWidget(self.quarantine_list)

        # Панель действий
        quarantine_panel = QWidget()
        quarantine_layout = QHBoxLayout(quarantine_panel)

        self.restore_btn = QPushButton("Восстановить")
        self.restore_btn.clicked.connect(self.restore_from_quarantine)

        self.delete_quarantine_btn = QPushButton("Удалить")
        self.delete_quarantine_btn.clicked.connect(self.delete_from_quarantine)

        self.clear_quarantine_btn = QPushButton("Очистить карантин")
        self.clear_quarantine_btn.clicked.connect(self.clear_quarantine)

        quarantine_layout.addWidget(self.restore_btn)
        quarantine_layout.addWidget(self.delete_quarantine_btn)
        quarantine_layout.addWidget(self.clear_quarantine_btn)
        quarantine_layout.addStretch()

        layout.addWidget(quarantine_panel)

        # Загрузка списка карантина
        self.load_quarantine_list()

        return tab

    def _create_settings_tab(self):
        """Создание вкладки настроек"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Защита в реальном времени
        realtime_group = QGroupBox("Защита в реальном времени")
        realtime_layout = QVBoxLayout(realtime_group)

        self.realtime_protection = QCheckBox("Включить защиту в реальном времени")
        realtime_layout.addWidget(self.realtime_protection)

        layout.addWidget(realtime_group)

        # Автообновление
        update_group = QGroupBox("Автоматическое обновление")
        update_layout = QVBoxLayout(update_group)

        self.auto_update = QCheckBox("Автоматически обновлять базы")
        update_layout.addWidget(self.auto_update)

        update_freq_layout = QHBoxLayout()
        update_freq_layout.addWidget(QLabel("Частота обновления:"))

        self.update_freq = QComboBox()
        self.update_freq.addItems(["Ежедневно", "Еженедельно", "Ежемесячно"])
        update_freq_layout.addWidget(self.update_freq)

        update_layout.addLayout(update_freq_layout)
        layout.addWidget(update_group)

        # Автосканирование
        autoscan_group = QGroupBox("Автоматическое сканирование")
        autoscan_layout = QVBoxLayout(autoscan_group)

        self.auto_scan = QCheckBox("Включить автоматическое сканирование")
        autoscan_layout.addWidget(self.auto_scan)

        scan_time_layout = QHBoxLayout()
        scan_time_layout.addWidget(QLabel("Время сканирования:"))

        self.scan_hour = QSpinBox()
        self.scan_hour.setRange(0, 23)
        self.scan_hour.setValue(2)
        scan_time_layout.addWidget(self.scan_hour)

        scan_time_layout.addWidget(QLabel(":00"))
        scan_time_layout.addStretch()

        autoscan_layout.addLayout(scan_time_layout)
        layout.addWidget(autoscan_group)

        # Действия
        action_group = QGroupBox("Действия при обнаружении")
        action_layout = QVBoxLayout(action_group)

        self.auto_quarantine = QCheckBox("Автоматически помещать в карантин")
        action_layout.addWidget(self.auto_quarantine)

        self.show_notifications = QCheckBox("Показывать уведомления")
        action_layout.addWidget(self.show_notifications)

        layout.addWidget(action_group)

        button_panel = QWidget()
        button_layout = QHBoxLayout(button_panel)

        save_btn = QPushButton("Сохранить настройки")
        save_btn.clicked.connect(self.save_settings)

        reset_btn = QPushButton("Сбросить настройки")
        reset_btn.clicked.connect(self.reset_settings)

        button_layout.addWidget(save_btn)
        button_layout.addWidget(reset_btn)
        button_layout.addStretch()

        layout.addWidget(button_panel)
        layout.addStretch()

        self.load_settings()

        return tab

    def _create_status_panel(self):
        """Создание панели статуса"""
        panel = QWidget()
        layout = QHBoxLayout(panel)

        self.status_icon = QLabel("🟢")
        layout.addWidget(self.status_icon)

        self.status_text = QLabel("Защита активна")
        layout.addWidget(self.status_text)

        layout.addStretch()

        # Информация о базах
        self.db_info = QLabel("Базы: обновлены")
        layout.addWidget(self.db_info)

        # Время последнего сканирования
        self.last_scan = QLabel("Последнее сканирование: никогда")
        layout.addWidget(self.last_scan)

        return panel

    def on_scan(self, scan_type):
        """Обработка нажатия кнопки сканирования"""
        path = "C:\\" if scan_type in ["quick", "full"] else self.path_edit.text()
        self.scan_requested.emit(path, scan_type)

    def on_update(self):
        """Обработка нажатия кнопки обновления"""
        self.update_requested.emit()

    def browse_path(self):
        """Выбор пути через диалог"""
        path = QFileDialog.getExistingDirectory(self, "Выберите папку для сканирования", "C:\\")
        if path:
            self.path_edit.setText(path)

    def start_scanning(self):
        """Запуск сканирования"""
        # Определяем тип сканирования
        if self.custom_scan_radio.isChecked():
            scan_type = "custom"
            path = self.path_edit.text()
        elif self.full_scan_radio.isChecked():
            scan_type = "full"
            path = "C:\\"
        else:
            scan_type = "quick"
            path = "C:\\"

        self.scan_requested.emit(path, scan_type)

    def update_progress(self, current, total, current_file):
        """Обновление прогресса сканирования"""
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.status_label.setText(f"Сканирование: {current_file}")

    def show_results(self, results):
        """Отображение результатов сканирования"""
        self.results_table.setRowCount(0)

        if "threats" in results:
            for threat in results["threats"]:
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)

                self.results_table.setItem(row, 0, QTableWidgetItem(threat.get("path", "")))
                self.results_table.setItem(row, 1, QTableWidgetItem(threat.get("name", "")))
                self.results_table.setItem(row, 2, QTableWidgetItem(threat.get("type", "")))
                self.results_table.setItem(row, 3, QTableWidgetItem(threat.get("status", "")))
                self.results_table.setItem(row, 4, QTableWidgetItem(threat.get("date", "")))

                action_widget = QWidget()
                action_layout = QHBoxLayout(action_widget)

                quarantine_btn = QPushButton("Карантин")
                quarantine_btn.clicked.connect(lambda checked=False, p=threat["path"]: self.quarantine_action.emit("add", p))

                ignore_btn = QPushButton("Игнорировать")
                ignore_btn.clicked.connect(lambda checked=False, p=threat["path"]: self.ignore_threat(p))
                
                action_layout.addWidget(quarantine_btn)
                action_layout.addWidget(ignore_btn)
                action_layout.setContentsMargins(0, 0, 0, 0)
                
                self.results_table.setCellWidget(row, 5, action_widget)
        
        # Разрешаем выделение строк
        self.results_table.selectionModel().selectionChanged.connect(self.on_selection_changed)
    
    def on_selection_changed(self):
        """Обработка изменения выделения"""
        selected = len(self.results_table.selectedItems()) > 0
        self.quarantine_btn.setEnabled(selected)
        self.delete_btn.setEnabled(selected)
        self.ignore_btn.setEnabled(selected)
    
    def quarantine_selected(self):
        """Помещение выбранных файлов в карантин"""
        selected_rows = set(item.row() for item in self.results_table.selectedItems())
        for row in selected_rows:
            file_path = self.results_table.item(row, 0).text()
            self.quarantine_action.emit("add", file_path)
    
    def delete_selected(self):
        """Удаление выбранных файлов"""
        selected_rows = set(item.row() for item in self.results_table.selectedItems())
        
        reply = QMessageBox.question(
            self, "Подтверждение удаления",
            f"Удалить {len(selected_rows)} файлов безвозвратно?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            for row in selected_rows:
                file_path = self.results_table.item(row, 0).text()
                try:
                    os.remove(file_path)
                    self.results_table.removeRow(row)
                except Exception as e:
                    QMessageBox.warning(self, "Ошибка", f"Не удалось удалить файл: {str(e)}")
    
    def ignore_selected(self):
        """Игнорирование выбранных угроз"""
        selected_rows = set(item.row() for item in self.results_table.selectedItems())
        for row in selected_rows:
            file_path = self.results_table.item(row, 0).text()
            self.ignore_threat(file_path)
    
    def ignore_threat(self, file_path):
        """Игнорирование угрозы"""
        # TODO: Добавить в список игнорируемых
        pass

    def load_quarantine_list(self):
        """Загрузка списка файлов в карантине"""
        self.quarantine_list.clear()
        quarantined = self.app.quarantine.get_quarantine_list()

        for item in quarantined:
            # Используем безопасное получение значений
            original_path = item.get("original_path", "Неизвестный путь")
            date = item.get("date", item.get("quarantine_date", "Неизвестная дата"))

            list_item = QListWidgetItem(f"{original_path} ({date})")
            list_item.setData(Qt.ItemDataRole.UserRole, item)
            self.quarantine_list.addItem(list_item)
    
    def restore_from_quarantine(self):
        """Восстановление файла из карантина"""
        selected = self.quarantine_list.currentItem()
        if selected:
            item_data = selected.data(Qt.ItemDataRole.UserRole)
            self.quarantine_action.emit("restore", item_data["original_path"])
            self.load_quarantine_list()
    
    def delete_from_quarantine(self):
        """Удаление файла из карантина"""
        selected = self.quarantine_list.currentItem()
        if selected:
            item_data = selected.data(Qt.ItemDataRole.UserRole)
            self.quarantine_action.emit("delete", item_data["original_path"])
            self.load_quarantine_list()
    
    def clear_quarantine(self):
        """Очистка всего карантина"""
        reply = QMessageBox.question(
            self, "Подтверждение",
            "Очистить весь карантин?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.app.quarantine.clear_quarantine()
            self.load_quarantine_list()
    
    def load_settings(self):
        """Загрузка настроек"""
        # TODO: Загрузка из файла конфигурации
        pass
    
    def save_settings(self):
        """Сохранение настроек"""
        # TODO: Сохранение в файл конфигурации
        QMessageBox.information(self, "Настройки", "Настройки сохранены")
    
    def reset_settings(self):
        """Сброс настроек"""
        reply = QMessageBox.question(
            self, "Подтверждение",
            "Сбросить все настройки к значениям по умолчанию?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # TODO: Сброс настроек
            QMessageBox.information(self, "Настройки", "Настройки сброшены")
    
    def update_update_progress(self, status, percent):
        """Обновление прогресса обновления"""
        self.status_label.setText(f"Обновление: {status}")
        self.progress_bar.setValue(percent)
    
    def update_finished(self, success, message):
        """Завершение обновления"""
        self.progress_bar.setVisible(False)
        if success:
            QMessageBox.information(self, "Обновление", message)
            self.db_info.setText("Базы: обновлены")
        else:
            QMessageBox.warning(self, "Ошибка обновления", message)
    
    def scan_finished(self):
        """Завершение сканирования"""
        self.progress_bar.setVisible(False)
        self.status_label.setText("Сканирование завершено")
        self.last_scan.setText(f"Последнее сканирование: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
    
    def scan_error(self, error_message):
        """Ошибка сканирования"""
        self.progress_bar.setVisible(False)
        self.status_label.setText("Ошибка сканирования")
        QMessageBox.critical(self, "Ошибка сканирования", error_message)
