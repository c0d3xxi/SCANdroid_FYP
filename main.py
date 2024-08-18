import sys
import os
import shutil
import subprocess
import re
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QLabel, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QFileDialog, QMessageBox, QStackedWidget, QFrame, QTextEdit, QTableWidget, QTableWidgetItem, QLineEdit, QComboBox, QRadioButton, QProgressBar)
from PyQt6.QtGui import QPixmap, QDragEnterEvent, QDropEvent
from PyQt6.QtCore import Qt, QThread, pyqtSignal

class ScanWorker(QThread):
    progress = pyqtSignal(int)
    scan_complete = pyqtSignal(str, str)

    def __init__(self, code_analysis_folder, result_file_path, custom_rules, use_default_rules):
        super().__init__()
        self.code_analysis_folder = code_analysis_folder
        self.result_file_path = result_file_path
        self.custom_rules = custom_rules
        self.use_default_rules = use_default_rules
        self.custom_rules_folder = 'customRules'

    def run(self):
        try:
            semgrep_command = '/opt/homebrew/bin/semgrep'  # Replace with actual path if needed
            if not os.access(semgrep_command, os.X_OK):
                os.chmod(semgrep_command, 0o755)

            files = os.listdir(self.code_analysis_folder)
            code_files = [file for file in files if file.endswith('.java') or file.endswith('.xml')]

            results = []

            # Copy custom rules to customRules folder
            copied_custom_rules = []
            for rule in self.custom_rules:
                dest_path = os.path.join(self.custom_rules_folder, os.path.basename(rule))
                shutil.copy(rule, dest_path)
                copied_custom_rules.append(dest_path)

            total_files = len(code_files)
            for i, file in enumerate(code_files):
                file_path = os.path.join(self.code_analysis_folder, file)
                try:
                    # Run Semgrep scan
                    command = [semgrep_command, 'scan']
                    if self.use_default_rules:
                        command.extend(['--config', 'auto'])
                    for rule in copied_custom_rules:
                        command.extend(['--config', rule])

                    command.append(file_path)
                    result = subprocess.run(command, capture_output=True, text=True, check=True)

                    filtered_output = [line for line in result.stdout.splitlines() if not re.search(r'https?://', line)]
                    results.append("\n".join(filtered_output))

                    # Run custom regex scans
                    regex_results = self.run_custom_regex_scan(file_path)
                    results.append("\n".join(regex_results))

                except subprocess.CalledProcessError as e:
                    results.append(f"Error scanning file {file_path}: {e}")
                except Exception as e:
                    results.append(f"Error scanning file {file_path}: {e}")

                progress_percentage = int(((i + 1) / total_files) * 100)
                self.progress.emit(progress_percentage)

            scan_output = "\n\n".join(results)
            with open(self.result_file_path, "w") as result_file:
                result_file.write(scan_output)
            self.scan_complete.emit("success", scan_output)

            # Delete the source code files after scan
            for file in code_files:
                os.remove(os.path.join(self.code_analysis_folder, file))
            
            # Delete the copied custom rules after scan
            for rule in copied_custom_rules:
                os.remove(rule)

        except Exception as e:
            self.scan_complete.emit("failure", str(e))

    def run_custom_regex_scan(self, file_path):
        regex_patterns = {
            "Hardcoded Credentials": r'(?i)(password|passwd|pwd|secret|token)\s*=\s*[\'\"]\w+[\'\"]',
            "Insecure URL": r'http://[^\s]+',
            "Weak Crypto Function": r'\b(md5|sha1|base64)\b',
            "Logging Sensitive Information": r'Log\.(v|d|i|w|e)\s*\(.+\)',
            "WebView Insecure Settings": r'webView\.getSettings\(\)\.set(JavaScriptEnabled|AllowFileAccess)\(true\)',
            "Insecure Random Number Generation": r'new\s+SecureRandom\s*\(\)',
            "SQL Injection Vulnerability": r'stmt\.execute(Query|Update)\(\s*["\'].*["\']\s*\)',
            "External Storage Access": r'Environment\.getExternalStorageDirectory\(\)',
            "Hardcoded IP Address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            "Untrusted Hostname Verifier": r'HostnameVerifier\s*=\s*new\s*HostnameVerifier\s*\(\s*\)\s*\{',
            "Debug Mode Enabled": r'Debug\s*=\s*true',
            "Hardcoded API Keys": r'(?i)(apikey|api_key|clientid|client_id)\s*=\s*[\'\"]\w+[\'\"]',
            "Sensitive URLs": r'(https://s3\.amazonaws\.com/[^\s]+|https://[^/]+\.amazonaws\.com/[^\s]+)'
        }
        
        results = []
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.readlines()
                for line_num, line in enumerate(content, start=1):
                    for description, pattern in regex_patterns.items():
                        matches = re.findall(pattern, line)
                        if matches:
                            results.append(f"\n--- {description} ---")
                            for match in matches:
                                results.append(f"Line {line_num}: {match.strip()}")
        except Exception as e:
            results.append(f"Error reading file {file_path} for regex scan: {e}")
        
        return results

class SCAndroid(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("SCAndroid")
        self.setGeometry(100, 100, 1200, 900)

        self.results_folder = 'results'
        self.history_folder = 'history'
        self.code_analysis_folder = 'code_analysis'
        self.custom_rules_folder = 'customRules'
        self.file_analysis_folder = 'file_analysis'
        
        os.makedirs(self.results_folder, exist_ok=True)
        os.makedirs(self.history_folder, exist_ok=True)
        os.makedirs(self.code_analysis_folder, exist_ok=True)
        os.makedirs(self.custom_rules_folder, exist_ok=True)
        os.makedirs(self.file_analysis_folder, exist_ok=True)

        self.init_ui()

    def init_ui(self):
        # Main widget container
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)

        # Main layout
        self.main_layout = QHBoxLayout(self.main_widget)

        # Sidebar (Menu)
        self.sidebar_frame = QFrame()
        self.sidebar_layout = QVBoxLayout(self.sidebar_frame)
        self.sidebar_layout.setSpacing(10)

        self.home_button = QPushButton("Home")
        self.apk_analyzer_button = QPushButton("APK File Analyzer")
        self.source_code_analyzer_button = QPushButton("Source Code Analyzer")
        self.history_button = QPushButton("History")
        self.result_button = QPushButton("Result")
        self.exit_button = QPushButton("Exit")

        self.sidebar_layout.addWidget(self.home_button)
        self.sidebar_layout.addWidget(self.apk_analyzer_button)
        self.sidebar_layout.addWidget(self.source_code_analyzer_button)
        self.sidebar_layout.addWidget(self.history_button)
        self.sidebar_layout.addWidget(self.result_button)
        self.sidebar_layout.addWidget(self.exit_button)
        self.sidebar_layout.addStretch(1)

        self.sidebar_frame.setFixedWidth(250)  # Fixed width for sidebar
        self.main_layout.addWidget(self.sidebar_frame)

        # Main content area
        self.content_area = QVBoxLayout()
        self.content_area.setSpacing(20)  # Add spacing between elements
        self.main_layout.addLayout(self.content_area, 1)

        # Header to display the name of the current page
        self.header_label = QLabel()
        self.header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.header_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        self.content_area.addWidget(self.header_label)

        # Stacked widget for different pages
        self.stacked_widget = QStackedWidget()
        self.content_area.addWidget(self.stacked_widget)

        # Home page
        self.home_widget = QWidget()
        self.home_layout = QVBoxLayout(self.home_widget)
        self.home_layout.setSpacing(20)

        # Top logo
        self.logo_label = QLabel()
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pixmap = QPixmap('logo.png')  # Ensure logo.png is in the same directory
        self.logo_label.setPixmap(pixmap.scaledToWidth(200, Qt.TransformationMode.SmoothTransformation))
        self.home_layout.addWidget(self.logo_label)

        # Welcome text
        self.welcome_text = QLabel("Welcome to SCAndroid, a SAST tool for JAVA based Android mobile applications.")
        self.welcome_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.home_layout.addWidget(self.welcome_text)

        # Description text
        self.description_text = QLabel("This is a SAST tool developed by psd.")
        self.description_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.home_layout.addWidget(self.description_text)

        self.home_layout.addStretch(1)
        self.home_widget.setLayout(self.home_layout)

        # APK File Analyzer page
        self.apk_analyzer_widget = QWidget()
        self.apk_analyzer_layout = QVBoxLayout(self.apk_analyzer_widget)
        self.apk_analyzer_layout.setSpacing(20)

        self.apk_output_file_label = QLabel("Output File Name:")
        self.apk_analyzer_layout.addWidget(self.apk_output_file_label)

        self.apk_output_file_input = QLineEdit()
        self.apk_analyzer_layout.addWidget(self.apk_output_file_input)

        # Drag and drop area for APK files
        self.apk_drag_area = QLabel("Drag and Drop APK Files Here")
        self.apk_drag_area.setStyleSheet("""
            QLabel {
                border: 2px dashed #089000;
                color: white;
                font-weight: bold;
                font-style: italic;
                height: 150px;  /* Triple the original length */
            }
        """)
        self.apk_drag_area.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.apk_drag_area.setAcceptDrops(True)
        self.apk_drag_area.dragEnterEvent = self.drag_enter_event
        self.apk_drag_area.dropEvent = self.apk_drop_event
        self.apk_analyzer_layout.addWidget(self.apk_drag_area)

        self.file_upload_button = QPushButton("Upload APK File")
        self.file_upload_button.clicked.connect(self.upload_file)
        self.apk_analyzer_layout.addWidget(self.file_upload_button)

        # Drag and drop area for YAML rules
        self.rules_drag_area_apk = QLabel("Drag and Drop .yaml Rules Here")
        self.rules_drag_area_apk.setStyleSheet("""
            QLabel {
                border: 2px dashed #089000;
                color: white;
                font-weight: bold;
                font-style: italic;
                height: 150px;  /* Triple the original length */
            }
        """)
        self.rules_drag_area_apk.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.rules_drag_area_apk.setAcceptDrops(True)
        self.rules_drag_area_apk.dragEnterEvent = self.drag_enter_event
        self.rules_drag_area_apk.dropEvent = self.rules_drop_event_apk
        self.apk_analyzer_layout.addWidget(self.rules_drag_area_apk)

        self.rules_upload_button_apk = QPushButton("Add Custom Rules")
        self.rules_upload_button_apk.clicked.connect(self.upload_rules_apk)
        self.apk_analyzer_layout.addWidget(self.rules_upload_button_apk)

        self.default_rules_notice_apk = QLabel("Do you wish to include default rules for the scan? (Note: If no custom rules are given then the scan will use default rules.)")
        self.apk_analyzer_layout.addWidget(self.default_rules_notice_apk)

        self.default_scan_radio_apk = QRadioButton("Include Default Scan")
        self.apk_analyzer_layout.addWidget(self.default_scan_radio_apk)

        self.uploaded_files_table_apk = QTableWidget()
        self.uploaded_files_table_apk.setColumnCount(2)
        self.uploaded_files_table_apk.setHorizontalHeaderLabels(['APK Files', 'Custom Rules'])
        self.uploaded_files_table_apk.horizontalHeader().setStretchLastSection(True)
        self.uploaded_files_table_apk.horizontalHeader().setDefaultSectionSize(200)  # Double the size
        self.apk_analyzer_layout.addWidget(self.uploaded_files_table_apk)

        self.clear_apk_table_button = QPushButton("Clear Table")
        self.clear_apk_table_button.clicked.connect(self.clear_apk_table)
        self.apk_analyzer_layout.addWidget(self.clear_apk_table_button)

        self.scan_button_apk = QPushButton("Scan")
        self.scan_button_apk.clicked.connect(self.scan_file_apk)
        self.apk_analyzer_layout.addWidget(self.scan_button_apk)

        self.apk_analyzer_layout.addStretch(1)
        self.apk_analyzer_widget.setLayout(self.apk_analyzer_layout)

        # Source Code Analyzer page
        self.source_code_analyzer_widget = QWidget()
        self.source_code_analyzer_layout = QVBoxLayout(self.source_code_analyzer_widget)
        self.source_code_analyzer_layout.setSpacing(20)

        self.source_code_output_file_label = QLabel("Output File Name:")
        self.source_code_analyzer_layout.addWidget(self.source_code_output_file_label)

        self.source_code_output_file_input = QLineEdit()
        self.source_code_analyzer_layout.addWidget(self.source_code_output_file_input)

        self.file_type_label = QLabel("Select File Type:")
        self.source_code_analyzer_layout.addWidget(self.file_type_label)

        self.file_type_combo_box = QComboBox()
        self.file_type_combo_box.addItems(["Java Source Code", "Android Manifest"])
        self.source_code_analyzer_layout.addWidget(self.file_type_combo_box)

        self.source_code_input = QTextEdit()
        self.source_code_input.setPlaceholderText("Enter source code here...")
        self.source_code_analyzer_layout.addWidget(self.source_code_input)

        self.source_code_rules_drag_area = QLabel("Drag and Drop .yaml Rules Here")
        self.source_code_rules_drag_area.setStyleSheet("""
            QLabel {
                border: 2px dashed #089000;
                color: white;
                font-weight: bold;
                font-style: italic;
                height: 150px;  /* Triple the original length */
            }
        """)
        self.source_code_rules_drag_area.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.source_code_rules_drag_area.setAcceptDrops(True)
        self.source_code_rules_drag_area.dragEnterEvent = self.drag_enter_event
        self.source_code_rules_drag_area.dropEvent = self.rules_drop_event_code
        self.source_code_analyzer_layout.addWidget(self.source_code_rules_drag_area)

        self.source_code_rules_upload_button = QPushButton("Upload .yaml Rules")
        self.source_code_rules_upload_button.clicked.connect(self.upload_rules_code)
        self.source_code_analyzer_layout.addWidget(self.source_code_rules_upload_button)

        self.source_code_default_rules_notice = QLabel("Do you wish to include default rules for the scan? (Note: If no custom rules are given then the scan will use default rules.)")
        self.source_code_analyzer_layout.addWidget(self.source_code_default_rules_notice)

        self.default_scan_radio_code = QRadioButton("Include Default Scan")
        self.source_code_analyzer_layout.addWidget(self.default_scan_radio_code)

        self.source_code_uploaded_rules_table = QTableWidget()
        self.source_code_uploaded_rules_table.setColumnCount(1)
        self.source_code_uploaded_rules_table.setHorizontalHeaderLabels(['Custom Rules'])
        self.source_code_uploaded_rules_table.horizontalHeader().setStretchLastSection(True)
        self.source_code_uploaded_rules_table.horizontalHeader().setDefaultSectionSize(400)  # Double the size
        self.source_code_analyzer_layout.addWidget(self.source_code_uploaded_rules_table)

        self.clear_source_code_table_button = QPushButton("Clear Table")
        self.clear_source_code_table_button.clicked.connect(self.clear_source_code_table)
        self.source_code_analyzer_layout.addWidget(self.clear_source_code_table_button)

        self.source_code_scan_button = QPushButton("Scan")
        self.source_code_scan_button.clicked.connect(self.scan_file_code)
        self.source_code_analyzer_layout.addWidget(self.source_code_scan_button)

        self.source_code_analyzer_layout.addStretch(1)
        self.source_code_analyzer_widget.setLayout(self.source_code_analyzer_layout)

        # History page
        self.history_widget = QWidget()
        self.history_layout = QVBoxLayout(self.history_widget)
        self.history_layout.setSpacing(20)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels(['Date-Time', 'Output File Name', 'APK file', 'Custom Rules'])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.horizontalHeader().setDefaultSectionSize(300)  # Double the size
        self.history_table.cellDoubleClicked.connect(self.load_scan_result)
        self.history_layout.addWidget(self.history_table)

        self.delete_history_button = QPushButton("Delete History")
        self.delete_history_button.clicked.connect(self.delete_history)
        self.history_layout.addWidget(self.delete_history_button)

        self.load_history()

        self.history_widget.setLayout(self.history_layout)

        # Result page
        self.result_widget = QWidget()
        self.result_layout = QVBoxLayout(self.result_widget)
        self.result_layout.setSpacing(20)

        self.result_text_box = QTextEdit()
        self.result_text_box.setReadOnly(True)
        self.result_layout.addWidget(self.result_text_box)

        self.result_widget.setLayout(self.result_layout)

        # Add widgets to stacked layout
        self.stacked_widget.addWidget(self.home_widget)
        self.stacked_widget.addWidget(self.apk_analyzer_widget)
        self.stacked_widget.addWidget(self.source_code_analyzer_widget)
        self.stacked_widget.addWidget(self.history_widget)
        self.stacked_widget.addWidget(self.result_widget)

        # Initial page
        self.show_home()

        # Connect buttons to change pages
        self.home_button.clicked.connect(self.show_home)
        self.apk_analyzer_button.clicked.connect(self.show_apk_analyzer)
        self.source_code_analyzer_button.clicked.connect(self.show_source_code_analyzer)
        self.history_button.clicked.connect(self.show_history)
        self.result_button.clicked.connect(self.show_result)
        self.exit_button.clicked.connect(self.close)

        self.current_custom_rules_apk = []
        self.current_custom_rules_code = []
        self.sidebar_hidden = True

    def show_home(self):
        self.header_label.setText("Home")
        self.stacked_widget.setCurrentWidget(self.home_widget)

    def show_apk_analyzer(self):
        self.header_label.setText("APK File Analyzer")
        self.stacked_widget.setCurrentWidget(self.apk_analyzer_widget)

    def show_source_code_analyzer(self):
        self.header_label.setText("Source Code Analyzer")
        self.stacked_widget.setCurrentWidget(self.source_code_analyzer_widget)

    def show_history(self):
        self.header_label.setText("History")
        self.stacked_widget.setCurrentWidget(self.history_widget)

    def show_result(self):
        self.header_label.setText("Result")
        self.stacked_widget.setCurrentWidget(self.result_widget)

    def drag_enter_event(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def apk_drop_event(self, event: QDropEvent):
        files = [url.toLocalFile() for url in event.mimeData().urls()]
        valid_files = [file for file in files if file.endswith('.apk')]
        if valid_files:
            for file in valid_files:
                row_count = self.uploaded_files_table_apk.rowCount()
                self.uploaded_files_table_apk.insertRow(row_count)
                self.uploaded_files_table_apk.setItem(row_count, 0, QTableWidgetItem(os.path.basename(file)))
        else:
            QMessageBox.warning(self, "Invalid File", "Please upload valid .apk files only.")

    def rules_drop_event_apk(self, event: QDropEvent):
        files = [url.toLocalFile() for url in event.mimeData().urls()]
        valid_files = [file for file in files if file.endswith('.yaml')]
        if valid_files:
            for file in valid_files:
                if file in self.current_custom_rules_apk:
                    QMessageBox.warning(self, "Duplicate File", "This file has already been uploaded.")
                else:
                    self.current_custom_rules_apk.append(file)
                    row_count = self.uploaded_files_table_apk.rowCount()
                    self.uploaded_files_table_apk.insertRow(row_count)
                    self.uploaded_files_table_apk.setItem(row_count, 1, QTableWidgetItem(os.path.basename(file)))
        else:
            QMessageBox.warning(self, "Invalid File", "Please upload valid .yaml files only.")

    def rules_drop_event_code(self, event: QDropEvent):
        files = [url.toLocalFile() for url in event.mimeData().urls()]
        valid_files = [file for file in files if file.endswith('.yaml')]
        if valid_files:
            for file in valid_files:
                if file in self.current_custom_rules_code:
                    QMessageBox.warning(self, "Duplicate File", "This file has already been uploaded.")
                else:
                    self.current_custom_rules_code.append(file)
                    row_count = self.source_code_uploaded_rules_table.rowCount()
                    self.source_code_uploaded_rules_table.insertRow(row_count)
                    self.source_code_uploaded_rules_table.setItem(row_count, 0, QTableWidgetItem(os.path.basename(file)))
        else:
            QMessageBox.warning(self, "Invalid File", "Please upload valid .yaml files only.")

    def upload_file(self):
        file_dialog = QFileDialog()
        file_paths, _ = file_dialog.getOpenFileNames(self, "Open APK File", "", "APK Files (*.apk)")

        if file_paths:
            valid_files = [file for file in file_paths if file.endswith('.apk')]
            if valid_files:
                for file in valid_files:
                    # Copy the file to file_analysis folder
                    shutil.copy(file, self.file_analysis_folder)
                    row_count = self.uploaded_files_table_apk.rowCount()
                    self.uploaded_files_table_apk.insertRow(row_count)
                    self.uploaded_files_table_apk.setItem(row_count, 0, QTableWidgetItem(os.path.basename(file)))
            else:
                QMessageBox.warning(self, "Invalid File", "Please upload valid .apk files only.")

    def upload_rules_apk(self):
        file_dialog = QFileDialog()
        file_paths, _ = file_dialog.getOpenFileNames(self, "Open YAML Files", "", "YAML Files (*.yaml)")

        if file_paths:
            valid_files = [file for file in file_paths if file.endswith('.yaml')]
            if valid_files:
                for file in valid_files:
                    if file in self.current_custom_rules_apk:
                        QMessageBox.warning(self, "Duplicate File", "This file has already been uploaded.")
                    else:
                        self.current_custom_rules_apk.append(file)
                        row_count = self.uploaded_files_table_apk.rowCount()
                        self.uploaded_files_table_apk.insertRow(row_count)
                        self.uploaded_files_table_apk.setItem(row_count, 1, QTableWidgetItem(os.path.basename(file)))
            else:
                QMessageBox.warning(self, "Invalid File", "Please upload valid .yaml files only.")

    def upload_rules_code(self):
        file_dialog = QFileDialog()
        file_paths, _ = file_dialog.getOpenFileNames(self, "Open YAML Files", "", "YAML Files (*.yaml)")

        if file_paths:
            valid_files = [file for file in file_paths if file.endswith('.yaml')]
            if valid_files:
                for file in valid_files:
                    if file in self.current_custom_rules_code:
                        QMessageBox.warning(self, "Duplicate File", "This file has already been uploaded.")
                    else:
                        self.current_custom_rules_code.append(file)
                        row_count = self.source_code_uploaded_rules_table.rowCount()
                        self.source_code_uploaded_rules_table.insertRow(row_count)
                        self.source_code_uploaded_rules_table.setItem(row_count, 0, QTableWidgetItem(os.path.basename(file)))
            else:
                QMessageBox.warning(self, "Invalid File", "Please upload valid .yaml files only.")

    def scan_file_apk(self):
        output_file_name = self.apk_output_file_input.text()
        if not output_file_name:
            QMessageBox.warning(self, "No Output File Name", "Please provide an output file name.")
            return

        use_default_rules = self.default_scan_radio_apk.isChecked()

        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_result = f"Scan results for {output_file_name} at {current_time}\n"
        
        result_file_path = os.path.join(self.results_folder, f"{output_file_name}.txt")
        
        apk_files = []
        for row in range(self.uploaded_files_table_apk.rowCount()):
            apk_item = self.uploaded_files_table_apk.item(row, 0)
            if apk_item:
                apk_files.append(apk_item.text())

        custom_rules_files = []
        for row in range(self.uploaded_files_table_apk.rowCount()):
            rules_item = self.uploaded_files_table_apk.item(row, 1)
            if rules_item:
                custom_rules_files.append(rules_item.text())

        if not apk_files:
            QMessageBox.warning(self, "No APK Files", "Please upload at least one APK file.")
            return

        custom_rules_str = ', '.join(custom_rules_files) if custom_rules_files else 'default rules'
        scan_result += f"\nAPK Files: {', '.join(apk_files)}\nCustom Rules: {custom_rules_str}"

        # Save history to file
        history_file_path = os.path.join(self.history_folder, "history.txt")
        with open(history_file_path, "a") as history_file:
            history_file.write(f"{current_time},{output_file_name},{', '.join(apk_files)},{custom_rules_str}\n")

        # Update history table
        self.history_table.insertRow(self.history_table.rowCount())
        self.history_table.setItem(self.history_table.rowCount() - 1, 0, QTableWidgetItem(current_time))
        self.history_table.setItem(self.history_table.rowCount() - 1, 1, QTableWidgetItem(output_file_name))
        self.history_table.setItem(self.history_table.rowCount() - 1, 2, QTableWidgetItem(', '.join(apk_files)))
        self.history_table.setItem(self.history_table.rowCount() - 1, 3, QTableWidgetItem(custom_rules_str))

        # Extract APK file using jadx
        try:
            for apk_file in apk_files:
                apk_path = os.path.join(self.file_analysis_folder, apk_file)
                output_dir = os.path.join(self.file_analysis_folder, f"decompiled_{apk_file}")
                os.makedirs(output_dir, exist_ok=True)
                subprocess.run(['jadx', '-d', output_dir, apk_path], check=True)
                
                # Look for important files to scan
                important_files = []
                manifest_path = os.path.join(output_dir, 'AndroidManifest.xml')
                if os.path.exists(manifest_path):
                    important_files.append(manifest_path)
                
                # Add any important Java files like MainActivity
                for root, dirs, files in os.walk(output_dir):
                    for file in files:
                        if file.endswith('.java') and 'MainActivity' in file:
                            important_files.append(os.path.join(root, file))

                # Show scan progress and run scan
                msg_box = QMessageBox(self)
                msg_box.setWindowTitle("Scanning")
                msg_box.setText("Scanning in progress. Please wait...")
                self.progress_bar = QProgressBar(msg_box)
                self.progress_bar.setGeometry(50, 50, 300, 20)
                msg_box.layout().addWidget(self.progress_bar)
                
                self.scan_worker = ScanWorker(output_dir, result_file_path, self.current_custom_rules_apk, use_default_rules)
                self.scan_worker.progress.connect(self.progress_bar.setValue)
                self.scan_worker.scan_complete.connect(self.on_scan_complete)
                self.scan_worker.start()

                msg_box.exec()

        except subprocess.CalledProcessError as e:
            QMessageBox.warning(self, "Extraction Failed", f"Failed to decompile APK file {apk_file}:\n{e}")

        # Clean up file_analysis folder after scan
        shutil.rmtree(self.file_analysis_folder)
        os.makedirs(self.file_analysis_folder, exist_ok=True)

    def scan_file_code(self):
        output_file_name = self.source_code_output_file_input.text()
        if not output_file_name:
            QMessageBox.warning(self, "No Output File Name", "Please provide an output file name.")
            return

        use_default_rules = self.default_scan_radio_code.isChecked()

        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_result = f"Scan results for {output_file_name} at {current_time}\n"
        
        result_file_path = os.path.join(self.results_folder, f"{output_file_name}.txt")
        
        file_type = self.file_type_combo_box.currentText()
        if file_type == "Java Source Code":
            file_extension = "java"
        else:
            file_extension = "xml"

        code_content = self.source_code_input.toPlainText()
        code_file_path = os.path.join(self.code_analysis_folder, f"{output_file_name}.{file_extension}")
        with open(code_file_path, "w") as code_file:
            code_file.write(code_content)

        custom_rules_files = []
        for row in range(self.source_code_uploaded_rules_table.rowCount()):
            rules_item = self.source_code_uploaded_rules_table.item(row, 0)
            if rules_item:
                custom_rules_files.append(rules_item.text())

        custom_rules_str = ', '.join(custom_rules_files) if custom_rules_files else 'default rules'
        scan_result += f"\nFile Type: {file_type}\nCustom Rules: {custom_rules_str}"

        # Save history to file
        history_file_path = os.path.join(self.history_folder, "history.txt")
        with open(history_file_path, "a") as history_file:
            history_file.write(f"{current_time},{output_file_name},{file_type},{custom_rules_str}\n")

        # Update history table
        self.history_table.insertRow(self.history_table.rowCount())
        self.history_table.setItem(self.history_table.rowCount() - 1, 0, QTableWidgetItem(current_time))
        self.history_table.setItem(self.history_table.rowCount() - 1, 1, QTableWidgetItem(output_file_name))
        self.history_table.setItem(self.history_table.rowCount() - 1, 2, QTableWidgetItem(file_type))
        self.history_table.setItem(self.history_table.rowCount() - 1, 3, QTableWidgetItem(custom_rules_str))

        # Show scan progress and run scan
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Scanning")
        msg_box.setText("Scanning in progress. Please wait...")
        self.progress_bar = QProgressBar(msg_box)
        self.progress_bar.setGeometry(50, 50, 300, 20)
        msg_box.layout().addWidget(self.progress_bar)
        
        self.scan_worker = ScanWorker(self.code_analysis_folder, result_file_path, self.current_custom_rules_code, use_default_rules)
        self.scan_worker.progress.connect(self.progress_bar.setValue)
        self.scan_worker.scan_complete.connect(self.on_scan_complete)
        self.scan_worker.start()

        msg_box.exec()

    def on_scan_complete(self, status, output):
        if status == "success":
            self.result_text_box.setText(output)
            self.show_result()
        else:
            QMessageBox.warning(self, "Scan Failed", f"Scanning failed with error:\n{output}")

    def load_history(self):
        self.history_table.setRowCount(0)  # Clear existing rows
        history_file_path = os.path.join(self.history_folder, "history.txt")
        if os.path.exists(history_file_path):
            with open(history_file_path, "r") as history_file:
                for line in history_file:
                    parts = line.strip().split(',')
                    date_time = parts[0]
                    output_file_name = parts[1]
                    apk_file = parts[2]
                    custom_rules = ', '.join(parts[3:])  # Join back any commas within custom rules
                    self.history_table.insertRow(self.history_table.rowCount())
                    self.history_table.setItem(self.history_table.rowCount() - 1, 0, QTableWidgetItem(date_time))
                    self.history_table.setItem(self.history_table.rowCount() - 1, 1, QTableWidgetItem(output_file_name))
                    self.history_table.setItem(self.history_table.rowCount() - 1, 2, QTableWidgetItem(apk_file))
                    self.history_table.setItem(self.history_table.rowCount() - 1, 3, QTableWidgetItem(custom_rules))

    def load_scan_result(self, row, column):
        if column == 1:  # Output File Name column
            output_file_name = self.history_table.item(row, column).text()
            result_file_path = os.path.join(self.results_folder, f"{output_file_name}.txt")
            if os.path.exists(result_file_path):
                with open(result_file_path, "r") as result_file:
                    self.result_text_box.setText(result_file.read())
                self.show_result()
            else:
                QMessageBox.warning(self, "File Not Found", f"Result file {output_file_name}.txt not found.")

    def delete_history(self):
        reply = QMessageBox.question(self, 'Delete History', 'Are you sure you want to delete all history? This action cannot be undone.', QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            # Clear history table
            self.history_table.setRowCount(0)
            # Delete all files in the history folder
            for file in os.listdir(self.history_folder):
                file_path = os.path.join(self.history_folder, file)
                os.remove(file_path)

    def clear_apk_table(self):
        self.uploaded_files_table_apk.setRowCount(0)
        self.current_custom_rules_apk.clear()

    def clear_source_code_table(self):
        self.source_code_uploaded_rules_table.setRowCount(0)
        self.current_custom_rules_code.clear()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SCAndroid()
    window.show()
    sys.exit(app.exec())

