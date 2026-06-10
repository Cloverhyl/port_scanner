import csv
import datetime
import os
from typing import List, Dict


CANONICAL_FIELDS = ['timestamp', 'target_ip', 'open_ports', 'services', 'scanned_ports_count', 'scan_duration_ms', 'notes']
# CSV headers to display 
CSV_HEADERS = ['时间戳', '目标IP', '开放端口', '服务', '扫描端口数', '扫描耗时(ms)', '备注']


def write_csv_backup(records: List[Dict], dest_dir: str = '.', filename: str = None) -> str:
    # 将标准化记录写为 CSV，并在 dest_dir 下生成备份文件
    if not filename:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'scan_{timestamp}.csv'
    path = os.path.join(dest_dir, filename)
    # 使用中文表头写入，字段顺序由 CANONICAL_FIELDS 对应 CSV_HEADERS 确定
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for rec in records:
            # 如果记录包含多个端口（分号分隔），则按“每端口一行”展开导出
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
                    # 为每个端口构建单独行
                    row_map = {
                        '时间戳': rec.get('timestamp', ''),
                        '目标IP': rec.get('target_ip', ''),
                        '开放端口': port,
                        '服务': svc,
                        '扫描端口数': rec.get('scanned_ports_count', ''),
                        '扫描耗时(ms)': rec.get('scan_duration_ms', ''),
                        '备注': rec.get('notes', '')
                    }
                    writer.writerow(row_map)
            else:
                # 无开放端口，写一行汇总记录
                row = {header: rec.get(key, '') for key, header in zip(CANONICAL_FIELDS, CSV_HEADERS)}
                writer.writerow(row)
    return path


if __name__ == '__main__':
    print('exporter.py: CSV helper module')
