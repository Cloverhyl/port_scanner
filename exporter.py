import csv
import datetime
import os
from typing import List, Dict


CANONICAL_FIELDS = ['timestamp', 'target_ip', 'open_ports', 'services', 'scanned_ports_count', 'scan_duration_ms', 'notes']
# CSV headers to display (Chinese)
CSV_HEADERS = ['时间戳', '目标IP', '开放端口', '服务', '扫描端口数', '扫描耗时(ms)', '备注']


def write_csv_backup(records: List[Dict], dest_dir: str = '.', filename: str = None) -> str:
    if not filename:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'scan_{timestamp}.csv'
    path = os.path.join(dest_dir, filename)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for rec in records:
            # Map canonical keys to Chinese header labels
            row = {header: rec.get(key, '') for key, header in zip(CANONICAL_FIELDS, CSV_HEADERS)}
            writer.writerow(row)
    return path


if __name__ == '__main__':
    print('exporter.py: CSV helper module')
