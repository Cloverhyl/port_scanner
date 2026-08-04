# 端口扫描器

轻量图形/命令行端口扫描工具（教学用途）。
- 目标：扫描局域网内主机的开放 TCP 端口，并在 GUI 中展示结果，同时提供简单的 CLI。当前实现并验证的主要模块包括 `cli_scanner.py`, `app_gui.py`, `scanner_core.py`, `exporter.py`, `ui/`。

## 免责声明
请勿在未经授权的网络或主机上运行本工具。任何未授权扫描可能违法或违反网络使用政策。使用前请获得目标所有者许可。

## 已实现的功能（核心）
- 目标解析：支持单 IP、CIDR、IP 范围的解析与输入校验（`scanner_core.parse_targets`，对过大子网/范围会被忽略并返回无效条目）。
- 端口扫描：基于 TCP Connect 的端口探测（线程池并发），可自定义端口集合或使用默认 TOP20。
- 服务推断：根据开放端口映射推断常见服务名称（如 22→SSH、80→HTTP），并在结果中展示。
- GUI：PySide6 实现的主窗口，中文界面，包含输入、并发滑条、开始/停止、导出 CSV 与进度表格；已加入法律免责声明并在输入处做友好校验提示。
- CSV 导出：`exporter.py` 提供带中文表头的导出与时间戳备份功能，导出同时可通过保存对话框指定路径。
- 文档：已更新 `README.md`。

## 当前代码/文件清单（建议提交到仓库）
- `cli_scanner.py`（CLI 入口，可选启动 GUI）
- `app_gui.py`（GUI 入口）
- `scanner_core.py`（核心解析与扫描逻辑）
- `exporter.py`（CSV 导出）
- `ui/`（`main_window.py` 与界面资源）
- `README.md`

## 已完成的最低验收项
- 能接受单 IP、CIDR、IP 范围并解析目标列表；对无效条目给出提示并忽略。
- 对目标执行 TCP Connect 扫描并在 GUI 表格中列出开放端口与推断的服务。
- 支持通过 GUI 导出 CSV 文件，并在脚本目录写入带时间戳的备份。

## 运行（开发）
建议先在虚拟环境中安装依赖：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install --upgrade --force-reinstall PySide6
```

启动 GUI：

```powershell
python app_gui.py
```

CLI 示例：

```powershell
python cli_scanner.py --targets "192.168.1.1,192.168.1.0/24" --ports "22,80" --export
```

## 输入验证
- 目标支持单个 IP、CIDR（/24）或范围（192.168.1.10-20）。
- CIDR/范围过大（>65536 主机）会被视为无效并被忽略。
- 端口必须在 1-65535 范围内。

GUI 中会在无效输入时显示提示对话框。

## 打包
使用 `pyinstaller` 打包为 Windows 可执行文件（示例）：

```bash
pyinstaller --noconfirm --onedir --windowed --add-data "ui;ui" app_gui.py
```

## 建议 
- 遵守法律与学校/单位的扫描政策。
