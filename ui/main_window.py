from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QProgressBar, QTableWidget, QTableWidgetItem, QSlider,
    QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal
from typing import List
from scanner_core import parse_targets, scan_host_ports, detect_services, TOP20
from exporter import write_csv_backup


class ScanThread(QThread):
    progress = Signal(int)
    result = Signal(dict)
    finished_sig = Signal()

    def __init__(self, targets: List[str], ports: List[int], concurrency: int, timeout: float):
        super().__init__()
        # `targets` here should already be a list of validated IP strings
        self.targets = targets
        self.ports = ports
        self.concurrency = concurrency
        self.timeout = timeout
        self._stopped = False

    def stop(self):
        self._stopped = True

    def run(self):
        ips = self.targets
        total = len(ips)
        for idx, ip in enumerate(ips, start=1):
            if self._stopped:
                break
            open_ports, elapsed_ms = scan_host_ports(ip, self.ports, concurrency=self.concurrency, timeout=self.timeout)
            services = detect_services(open_ports)
            rec = {
                'timestamp': __import__('time').strftime('%Y-%m-%d %H:%M:%S'),
                'target_ip': ip,
                'open_ports': ';'.join(str(p) for p in open_ports),
                'services': ';'.join(services),
                'scanned_ports_count': len(self.ports),
                'scan_duration_ms': elapsed_ms,
                'notes': ''
            }
            self.result.emit(rec)
            self.progress.emit(int(idx * 100 / total) if total else 100)
        self.finished_sig.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('端口扫描器')
        self.resize(800, 600)

        

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(10)
        layout.setContentsMargins(12, 12, 12, 12)

        # Inputs
        row1 = QHBoxLayout()
        row1.addWidget(QLabel('目标（逗号分隔 / CIDR / 范围）：'))
        self.targets_edit = QLineEdit()
        self.targets_edit.setPlaceholderText('例如：192.168.1.1,192.168.1.0/24,192.168.1.10-20')
        row1.addWidget(self.targets_edit)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel('端口（逗号分隔，默认 Top20）：'))
        self.ports_edit = QLineEdit()
        self.ports_edit.setPlaceholderText('例如：22,80 或留空')
        row2.addWidget(self.ports_edit)
        layout.addLayout(row2)

        # Disclaimer / legal reminder
        disclaimer = QLabel('警告：请勿扫描未授权的网络或主机；请遵守当地法律与学校/单位规定。')
        disclaimer.setStyleSheet('color: red;')
        layout.addWidget(disclaimer)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel('并发数：'))
        self.concurrency_slider = QSlider(Qt.Horizontal)
        self.concurrency_slider.setMinimum(1)
        self.concurrency_slider.setMaximum(50)
        self.concurrency_slider.setValue(5)
        row3.addWidget(self.concurrency_slider)
        self.concurrency_label = QLabel('5')
        row3.addWidget(self.concurrency_label)
        self.concurrency_slider.valueChanged.connect(lambda v: self.concurrency_label.setText(str(v)))
        layout.addLayout(row3)

        # Controls
        ctrls = QHBoxLayout()
        self.start_btn = QPushButton('开始扫描')
        self.stop_btn = QPushButton('停止')
        self.stop_btn.setEnabled(False)
        self.export_btn = QPushButton('导出 CSV')
        ctrls.addWidget(self.start_btn)
        ctrls.addWidget(self.stop_btn)
        ctrls.addWidget(self.export_btn)
        layout.addLayout(ctrls)

        # Progress & table
        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(['时间戳','目标IP','开放端口','服务','扫描端口数','扫描耗时(ms)','备注'])
        layout.addWidget(self.table)

        # State
        self.records = []
        self.scan_thread = None

        # Connections
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.export_btn.clicked.connect(self.export_csv)

    def start_scan(self):
        targets_text = self.targets_edit.text().strip()
        if not targets_text:
            QMessageBox.warning(self, '输入错误', '请填写目标 IP/CIDR/范围')
            return
        targets = [t.strip() for t in targets_text.split(',') if t.strip()]
        ips, invalids = parse_targets(targets)
        if invalids:
            QMessageBox.warning(self, '输入提醒', f'以下目标格式无效或过大，已忽略:\n{" ,".join(invalids)}')
        if not ips:
            QMessageBox.warning(self, '输入错误', '没有有效的目标 IP，无法开始扫描')
            return

        ports_text = self.ports_edit.text().strip()
        ports = self._parse_ports(ports_text)
        if ports is None:
            return
        concurrency = self.concurrency_slider.value()
        timeout = 1.0

        self.records = []
        self.table.setRowCount(0)
        self.progress.setValue(0)

        self.scan_thread = ScanThread(targets=ips, ports=ports, concurrency=concurrency, timeout=timeout)
        self.scan_thread.result.connect(self.on_result)
        self.scan_thread.progress.connect(self.progress.setValue)
        self.scan_thread.finished_sig.connect(self.on_finished)
        self.scan_thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_thread = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def on_result(self, rec: dict):
        # keep canonical record for CSV export
        self.records.append(rec)

        # display one port per row with corresponding service
        open_ports_field = rec.get('open_ports', '')
        services_field = rec.get('services', '')
        if isinstance(open_ports_field, str):
            ports = [p for p in open_ports_field.split(';') if p]
        else:
            ports = [str(p) for p in open_ports_field]
        if isinstance(services_field, str):
            services = [s for s in services_field.split(';') if s]
        else:
            services = [str(s) for s in services_field]

        if ports:
            for i, port in enumerate(ports):
                svc = services[i] if i < len(services) else ''
                row = self.table.rowCount()
                self.table.insertRow(row)
                values = [rec.get('timestamp',''), rec.get('target_ip',''), port, svc, rec.get('scanned_ports_count',''), rec.get('scan_duration_ms',''), rec.get('notes','')]
                for col, val in enumerate(values):
                    item = QTableWidgetItem(str(val))
                    item.setTextAlignment(Qt.AlignCenter)
                    self.table.setItem(row, col, item)
        else:
            # no open ports: insert a single summary row with empty port/service
            row = self.table.rowCount()
            self.table.insertRow(row)
            for col, key in enumerate(['timestamp','target_ip','open_ports','services','scanned_ports_count','scan_duration_ms','notes']):
                item = QTableWidgetItem(str(rec.get(key, '')))
                item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, col, item)

    def on_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        QMessageBox.information(self, '完成', '扫描完成')

    def _parse_ports(self, s: str) -> List[int]:
        if not s:
            return TOP20
        parts = s.split(',')
        out = []
        invalid = []
        for p in parts:
            p = p.strip()
            if not p:
                continue
            try:
                val = int(p)
                if 1 <= val <= 65535:
                    out.append(val)
                else:
                    invalid.append(p)
            except Exception:
                invalid.append(p)
        if invalid:
            QMessageBox.warning(self, '端口格式错误', f'以下端口无效：{",".join(invalid)}')
            return None
        return out or TOP20

    def export_csv(self):
        if not self.records:
            QMessageBox.information(self, '无数据', '当前没有扫描记录可导出')
            return
        path, _ = QFileDialog.getSaveFileName(self, '保存 CSV', 'scan.csv', 'CSV 文件 (*.csv)')
        if path:
            try:
                write_csv_backup(self.records, dest_dir='.', filename=path.split('\\')[-1])
                QMessageBox.information(self, '已保存', f'已保存: {path}')
            except Exception as e:
                QMessageBox.critical(self, '错误', str(e))
