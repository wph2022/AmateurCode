#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wph_AUTOChargeLOG(ACL) V1.1 - 优化版

设计目标：
1. 现代扁平化 UI：统一配色、低噪声、清晰分区。
2. 模块独立：时间同步、解析器、分析引擎、ADB、I2C、Worker、UI 分离。
3. 精简逻辑：统一 busy 状态、统一日志输出、减少重复代码。
4. 清晰注释：每个模块说明职责和输入/输出。
"""

from __future__ import annotations

import csv
import datetime as dt
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from PySide6.QtCore import QEvent, QThread, QTimer, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QIcon, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)


# ========================= 全局常量 =========================
APP_TITLE = "Wph_AUTOChargeLOG(ACL)_V1.1 - 优化版"
LOG_EXTS = {".log", ".txt", ".out", ".csv"}
MAX_SCAN_LINES = 5_000_000
MAX_TABLE_ROWS = 200_000
MAX_UI_ROWS = 1_000
MAX_DYNAMIC_COLS = 40

SKIP_DIR_NAMES = {
    ".git", ".svn", "__pycache__", "node_modules", "images", "image", "img", "video", "videos", "media",
    "cache", "caches", "tmp", "temp", "download", "downloads", "apks", "apk", "obb", "dcim", "pictures", "movies", "music",
}
NAME_KEYWORDS = ("logcat", "bugreport", "tombstone", "anr", "dropbox", "kmsg", "kernel")


# ========================= 时间同步模块 =========================
class TimeSyncEstimator:
    """基于 kernel log 锚点拟合偏移，将内核秒时间映射到 Android 时间。"""

    _re_kernel_sec = re.compile(r"\[\s*(\d+(?:\.\d+)?)\s*\]")
    _re_android_tag = re.compile(
        r"android\s*time\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)",
        re.IGNORECASE,
    )
    _re_android_dt = re.compile(r"\b(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\b")

    def __init__(self) -> None:
        self.offset_seconds: Optional[float] = None
        self.samples: List[Tuple[float, float]] = []

    @staticmethod
    def _parse_datetime(text: str) -> Optional[dt.datetime]:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return dt.datetime.strptime(text.strip(), fmt)
            except Exception:
                continue
        return None

    def _extract_anchor(self, line: str) -> Optional[Tuple[float, dt.datetime]]:
        km = self._re_kernel_sec.search(line)
        if not km:
            return None
        try:
            ksec = float(km.group(1))
        except Exception:
            return None

        tm = self._re_android_tag.search(line) or self._re_android_dt.search(line)
        if not tm:
            return None
        adt = self._parse_datetime(tm.group(1))
        return (ksec, adt) if adt else None

    def fit_from_files(
        self,
        files: List[Path],
        should_stop: Optional[Callable[[], bool]] = None,
        max_lines_per_file: int = 250_000,
        max_anchors: int = 60,
        log: Callable[[str], None] = lambda _m: None,
    ) -> None:
        self.offset_seconds = None
        self.samples.clear()

        anchors = 0
        for fp in files:
            if should_stop and should_stop():
                return
            low_name = fp.name.lower()
            if "kernel" not in low_name and "kmsg" not in low_name:
                continue
            try:
                with fp.open("r", encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f):
                        if should_stop and should_stop():
                            return
                        if i >= max_lines_per_file:
                            break
                        low = line.lower()
                        if "android time" not in low and " utc" not in low:
                            continue
                        a = self._extract_anchor(line)
                        if not a:
                            continue
                        ksec, adt = a
                        self.samples.append((ksec, adt.timestamp() - ksec))
                        anchors += 1
                        if anchors >= max_anchors:
                            break
            except Exception as e:
                log(f"[WARN] TimeSync 读取失败：{fp} ({e})")
            if anchors >= max_anchors:
                break

        if not self.samples:
            return

        offsets = sorted(x[1] for x in self.samples)
        mid = len(offsets) // 2
        self.offset_seconds = offsets[mid] if len(offsets) % 2 else (offsets[mid - 1] + offsets[mid]) / 2

    def kernel_to_android_str(self, kernel_sec: float) -> str:
        if self.offset_seconds is None:
            return ""
        try:
            d = dt.datetime.fromtimestamp(kernel_sec + self.offset_seconds)
            micro = int(round((kernel_sec - int(kernel_sec)) * 1_000_000))
            return d.replace(microsecond=micro).strftime("%Y-%m-%d %H:%M:%S.%f")
        except Exception:
            return ""


# ========================= 日志解析模块 =========================
class BaseLogParser:
    """解析器基类：定义匹配和行解析接口。"""

    log_type: str = "base"
    keyword: str = ""

    _re_ts_full = re.compile(r"\b(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\b")
    _re_ts_md = re.compile(r"\b(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\b")
    _re_ts_hms = re.compile(r"\b(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\b")
    _re_ts_bracket = re.compile(r"\[\s*(\d+(?:\.\d+)?)\s*\]")

    def match(self, line: str) -> bool:
        return not self.keyword or self.keyword.lower() in line.lower()

    def extract_timestamp(self, line: str) -> str:
        text = line.strip()
        for reg in (self._re_ts_full, self._re_ts_md, self._re_ts_hms):
            m = reg.search(text)
            if m:
                return m.group(1)
        m = self._re_ts_bracket.search(text)
        return m.group(1) if m else ""

    def parse_line(self, line: str) -> Dict[str, str]:
        raise NotImplementedError


class HealthdParser(BaseLogParser):
    """解析 `healthd: battery ...` 格式。"""

    log_type = "healthd"
    keyword = "healthd: battery"
    base_keys = ["l", "v", "t", "h", "st", "c", "fc", "cc", "chg"]

    _re_payload = re.compile(r"healthd:\s*battery\s+(.*)", re.IGNORECASE)
    _split = re.compile(r"[\s,]+")

    def parse_line(self, line: str) -> Dict[str, str]:
        m = self._re_payload.search(line)
        if not m:
            return {}

        kv: Dict[str, str] = {}
        for token in self._split.split(m.group(1).strip()):
            if not token or (":" not in token and "=" not in token):
                continue
            sep = ":" if ":" in token else "="
            k, v = token.split(sep, 1)
            kv[k.strip()] = v.strip()

        row = {k: kv.get(k, "") for k in self.base_keys}
        row["timestamp"] = self.extract_timestamp(line)
        row["log_type"] = self.log_type
        return row


class VbatParser(BaseLogParser):
    """解析 `Vbat=...` 格式。"""

    log_type = "vbat"
    keyword = "vbat="
    _split = re.compile(r"[\s,]+")

    def parse_line(self, line: str) -> Dict[str, str]:
        idx = line.lower().find("vbat=")
        if idx < 0:
            return {}

        kv: Dict[str, str] = {}
        for token in self._split.split(line[idx:].strip()):
            if not token or (":" not in token and "=" not in token):
                continue
            sep = ":" if ":" in token else "="
            k, v = token.split(sep, 1)
            kv[k.strip()] = v.strip()

        if not kv:
            return {}
        kv["timestamp"] = self.extract_timestamp(line)
        kv["log_type"] = self.log_type
        return kv


@dataclass
class ParseResult:
    """分析结果数据对象，供 UI 展示与 CSV 导出复用。"""

    parser_name: str
    source: str
    files_scanned: int
    lines_scanned: int
    matched_lines: int
    parsed_rows: int
    columns: List[str]
    records: List[Dict[str, str]]
    rows: List[Tuple[str, ...]]


# ========================= 分析引擎模块 =========================
class LogAnalyzer:
    """扫描目标路径并调用解析器，输出 ParseResult。"""

    def __init__(self) -> None:
        self.log_message: Callable[[str], None] = lambda _m: None
        self.timesync = TimeSyncEstimator()

    @staticmethod
    def _natural_key(text: str) -> List[object]:
        return [int(p) if p.isdigit() else p.lower() for p in re.split(r"(\d+)", text)]

    def _iter_lines(self, path: Path) -> Iterable[str]:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                yield from f
        except Exception as e:
            self.log_message(f"[WARN] 无法读取文件：{path} ({e})")

    def _collect_files(self, path: Path) -> List[Path]:
        if path.is_file():
            return [path]

        scan_root = path / "mobilelog" if (path / "mobilelog").is_dir() else path
        out: List[Path] = []
        try:
            for root, dirs, files in os.walk(scan_root, topdown=True):
                dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIR_NAMES]
                for name in files:
                    low = name.lower()
                    p = Path(root) / name
                    if p.suffix.lower() in LOG_EXTS or any(k in low for k in NAME_KEYWORDS):
                        out.append(p)
        except Exception as e:
            self.log_message(f"[WARN] 遍历目录失败：{scan_root} ({e})")

        out.sort(key=lambda x: self._natural_key(str(x).lower()))
        return out

    @staticmethod
    def _is_kernel_seconds(ts: str) -> bool:
        ts = ts.strip()
        if not ts or any(c in ts for c in "-:"):
            return False
        try:
            float(ts)
            return True
        except Exception:
            return False

    def _apply_timesync(self, row: Dict[str, str]) -> None:
        ts = row.get("timestamp", "").strip()
        if not ts:
            return
        if not self._is_kernel_seconds(ts):
            row["android_time"] = ts
            return

        row["kernel_ts"] = ts
        if self.timesync.offset_seconds is None:
            return
        try:
            at = self.timesync.kernel_to_android_str(float(ts))
            if at:
                row["android_time"] = at
        except Exception:
            pass

    def _build_columns(self, parser: BaseLogParser, records: List[Dict[str, str]]) -> List[str]:
        fixed = ["android_time", "kernel_ts", "log_type", "log_file"]
        if isinstance(parser, HealthdParser):
            return fixed + [k for k in parser.base_keys if k not in fixed]

        extra: List[str] = []
        seen = set(fixed)
        for rec in records[:3000]:
            for k in rec.keys():
                if k in seen:
                    continue
                seen.add(k)
                extra.append(k)
                if len(extra) >= MAX_DYNAMIC_COLS:
                    break
            if len(extra) >= MAX_DYNAMIC_COLS:
                break
        return fixed + extra

    def analyze_path(
        self,
        path: Path,
        parser: BaseLogParser,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> ParseResult:
        files = self._collect_files(path)

        self.log_message("[INFO] TimeSync: 尝试拟合内核秒到 Android 时间映射...")
        self.timesync.fit_from_files(files, should_stop=should_stop, log=self.log_message)
        if self.timesync.offset_seconds is None:
            self.log_message("[WARN] TimeSync: 未找到锚点，将保留原始时间")
        else:
            self.log_message("[OK] TimeSync: 拟合成功")

        records: List[Dict[str, str]] = []
        lines_scanned, matched_lines = 0, 0

        for fp in files:
            if should_stop and should_stop():
                break
            for line in self._iter_lines(fp):
                if should_stop and should_stop():
                    break

                lines_scanned += 1
                if lines_scanned >= MAX_SCAN_LINES:
                    self.log_message(f"[WARN] 达到最大扫描行数限制({MAX_SCAN_LINES})")
                    break

                if not parser.match(line):
                    continue

                matched_lines += 1
                row = parser.parse_line(line)
                if not row:
                    continue

                row["log_file"] = fp.name
                self._apply_timesync(row)
                records.append(row)

                if len(records) >= MAX_TABLE_ROWS:
                    self.log_message(f"[WARN] 达到最大解析行数限制({MAX_TABLE_ROWS})")
                    break

            if lines_scanned >= MAX_SCAN_LINES or len(records) >= MAX_TABLE_ROWS:
                break

        columns = self._build_columns(parser, records)
        rows = [tuple(str(r.get(c, "")) for c in columns) for r in records]

        return ParseResult(
            parser_name=parser.log_type,
            source=str(path),
            files_scanned=len(files),
            lines_scanned=lines_scanned,
            matched_lines=matched_lines,
            parsed_rows=len(records),
            columns=columns,
            records=records,
            rows=rows,
        )


# ========================= ADB 模块 =========================
class AdbError(RuntimeError):
    pass


class AdbClient:
    """ADB 调用封装：集中处理可用性、设备发现、命令执行。"""

    def __init__(self, exe: str = "adb") -> None:
        self.exe = exe

    def ensure_available(self) -> None:
        try:
            subprocess.run([self.exe, "version"], capture_output=True, text=True, check=True)
        except Exception as e:
            raise AdbError("adb 不可用：请安装 Android Platform Tools 并配置 PATH") from e

    def devices(self) -> List[Tuple[str, str]]:
        p = subprocess.run([self.exe, "devices", "-l"], capture_output=True, text=True, timeout=6)
        lines = p.stdout.strip().splitlines()
        out: List[Tuple[str, str]] = []
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] == "device":
                serial = parts[0]
                desc = " ".join(parts[2:]) if len(parts) > 2 else ""
                out.append((serial, desc))
        return out

    def run(self, serial: str, args: List[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        return subprocess.run([self.exe, "-s", serial] + args, capture_output=True, text=True, timeout=timeout)

    def adb_root(self, serial: str) -> Tuple[bool, str]:
        try:
            p = self.run(serial, ["root"], timeout=8)
            msg = (p.stdout or "") + (p.stderr or "")
            low = msg.lower()
            ok = p.returncode == 0 and (
                "already running as root" in low or "restarting adbd as root" in low
            )
            return ok, msg.strip()
        except Exception as e:
            return False, str(e)

    def su_root_ok(self, serial: str) -> bool:
        try:
            p = self.run(serial, ["shell", "su", "-c", "id"], timeout=6)
            msg = (p.stdout or "") + (p.stderr or "")
            return p.returncode == 0 and "uid=0" in msg
        except Exception:
            return False

    def pull_mobilelog(self, serial: str, export_root: Path) -> Tuple[bool, str]:
        export_root.mkdir(parents=True, exist_ok=True)
        target = export_root / "mobilelog"
        target.mkdir(parents=True, exist_ok=True)

        for src in ("/data/debuglogger/mobilelog", "/sdcard/debuglogger/mobilelog"):
            p = self.run(serial, ["pull", src, str(target)], timeout=120)
            if p.returncode == 0:
                return True, f"[OK] 拉取成功：{src} -> {target}"
        return False, "[ERROR] mobilelog 拉取失败（已尝试 /data 与 /sdcard）"


# ========================= I2C 模块 =========================
class I2CService:
    """I2C 命令构造与输出解析。可单元测试，不依赖 UI。"""

    @staticmethod
    def parse_int(text: str) -> int:
        s = text.strip()
        return int(s, 16) if s.lower().startswith("0x") else int(s, 10)

    @staticmethod
    def parse_i2cget_output(out: str) -> int:
        lines = out.strip().splitlines()
        if not lines:
            raise ValueError("i2cget 输出为空")
        return I2CService.parse_int(lines[-1].strip())

    @staticmethod
    def cmd_read(bus: int, addr: str, reg: str) -> str:
        return f"i2cget -f -y {bus} {addr} {reg}"

    @staticmethod
    def cmd_write(bus: int, addr: str, reg: str, val: str) -> str:
        return f"i2cset -f -y {bus} {addr} {reg} {val} b"

    @staticmethod
    def cmd_dump(bus: int, addr: str) -> str:
        return f"i2cdump -f -y {bus} {addr} b"

    @staticmethod
    def extract_dump_table(out: str) -> str:
        rows = [ln.rstrip() for ln in out.splitlines() if re.match(r"^\s*[0-9a-fA-F]{2}:\s+", ln)]
        return "\n".join(rows) if rows else out.strip()


# ========================= Worker 模块 =========================
class AnalysisWorker(QThread):
    log_signal = Signal(str)
    result_signal = Signal(object)

    def __init__(self, analyzer: LogAnalyzer, path: Path, parser: BaseLogParser) -> None:
        super().__init__()
        self.analyzer = analyzer
        self.path = path
        self.parser = parser

    def run(self) -> None:
        try:
            self.analyzer.log_message = self.log_signal.emit
            self.log_signal.emit(f"[INFO] 开始分析：{self.path} | mode={self.parser.log_type}")
            result = self.analyzer.analyze_path(self.path, self.parser, should_stop=self.isInterruptionRequested)
            if not self.isInterruptionRequested():
                self.result_signal.emit(result)
                self.log_signal.emit("[OK] 分析完成")
        except Exception as e:
            self.log_signal.emit(f"[ERROR] 分析失败：{e}")


class ExportAnalyzeWorker(QThread):
    log_signal = Signal(str)
    result_signal = Signal(object)

    def __init__(self, adb: AdbClient, analyzer: LogAnalyzer, serials: List[str], export_dir: Path, parser: BaseLogParser) -> None:
        super().__init__()
        self.adb = adb
        self.analyzer = analyzer
        self.serials = serials
        self.export_dir = export_dir
        self.parser = parser

    def run(self) -> None:
        try:
            self.adb.ensure_available()
        except Exception as e:
            self.log_signal.emit(f"[ERROR] {e}")
            return

        for serial in self.serials:
            if self.isInterruptionRequested():
                return

            ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            root = self.export_dir / f"export_{serial}_{ts}"

            ok, msg = self.adb.pull_mobilelog(serial, root)
            self.log_signal.emit(f"[INFO] device={serial} {msg}")
            if not ok:
                continue

            path = root / "mobilelog"
            if not path.exists():
                path = root

            result = self.analyzer.analyze_path(path, self.parser, should_stop=self.isInterruptionRequested)
            if self.isInterruptionRequested():
                return
            self.result_signal.emit(result)


class ShellCmdWorker(QThread):
    done_signal = Signal(int, str, str)

    def __init__(self, adb: AdbClient, serial: str, shell_cmd: str, timeout: int = 10, auto_root: bool = True) -> None:
        super().__init__()
        self.adb = adb
        self.serial = serial
        self.shell_cmd = shell_cmd
        self.timeout = timeout
        self.auto_root = auto_root

    def _run_shell(self, cmd: List[str]) -> Tuple[int, str, str]:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        return p.returncode, (p.stdout or ""), (p.stderr or "")

    def run(self) -> None:
        try:
            cmd = [self.adb.exe, "-s", self.serial, "shell", self.shell_cmd]
            rc, out, err = self._run_shell(cmd)

            if self.auto_root and "permission denied" in (err or "").lower():
                ok, _ = self.adb.adb_root(self.serial)
                if ok:
                    rc, out, err = self._run_shell(cmd)
                elif self.adb.su_root_ok(self.serial):
                    su_cmd = [self.adb.exe, "-s", self.serial, "shell", "su", "-c", self.shell_cmd]
                    rc, out, err = self._run_shell(su_cmd)
                else:
                    err = (err.strip() + "\n[NO-ROOT] 无法获取 root 权限。").strip()

            self.done_signal.emit(rc, out, err)
        except Exception as e:
            self.done_signal.emit(1, "", str(e))


class CsvExportWorker(QThread):
    done_signal = Signal(bool, str)

    def __init__(self, file_path: str, columns: List[str], rows: List[Tuple[str, ...]]) -> None:
        super().__init__()
        self.file_path = file_path
        self.columns = columns
        self.rows = rows

    def run(self) -> None:
        try:
            with open(self.file_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(self.columns)
                for row in self.rows:
                    if len(row) != len(self.columns):
                        row = tuple(list(row) + [""] * (len(self.columns) - len(row)))[: len(self.columns)]
                    writer.writerow(row)
            self.done_signal.emit(True, self.file_path)
        except Exception as e:
            self.done_signal.emit(False, str(e))


# ========================= UI 主窗口 =========================
class ChargeAutoTool(QMainWindow):
    """主窗口：只负责交互与展示，不承担核心解析逻辑。"""

    def __init__(self) -> None:
        super().__init__()

        self.adb = AdbClient()
        self.analyzer = LogAnalyzer()
        self.i2c_service = I2CService()

        self.current_mode = "Healthd"
        self.current_result: Optional[ParseResult] = None
        self.parsers: Dict[str, BaseLogParser] = {
            "Healthd": HealthdParser(),
            "Vbat": VbatParser(),
        }

        # 状态控制
        self._busy_analysis = False
        self._busy_export = False
        self._busy_csv = False
        self._busy_reg = False
        self._log_queue: List[str] = []
        self._reg_log_queue: List[str] = []

        self._build_ui()
        self._init_timers()
        self._poll_devices_once()

    # -------- 样式与 UI --------
    @staticmethod
    def _btn_css(bg: str, hover: str) -> str:
        return (
            "QPushButton{background:%s;color:#fff;border:none;border-radius:6px;padding:6px 10px;font-weight:600;}"
            "QPushButton:hover{background:%s;}"
            "QPushButton:disabled{background:#9AA0A6;color:#ECEFF4;}"
        ) % (bg, hover)

    def _build_ui(self) -> None:
        self.setWindowTitle(APP_TITLE)
        self.resize(1260, 760)
        self.setStyleSheet(
            "QMainWindow{background:#F5F6F8;font-family:'Microsoft YaHei',Arial;}"
            "QGroupBox{background:#fff;border:1px solid #D9DCE1;border-radius:8px;margin-top:10px;font-weight:bold;}"
            "QGroupBox::title{subcontrol-origin:margin;left:10px;padding:0 6px;color:#374151;}"
            "QTextEdit,QListWidget,QTreeWidget,QLineEdit,QComboBox,QSpinBox{background:#fff;border:1px solid #D9DCE1;border-radius:6px;}"
        )

        root = QWidget()
        self.setCentralWidget(root)
        root_layout = QVBoxLayout(root)

        self.splitter = QSplitter(Qt.Horizontal)
        root_layout.addWidget(self.splitter)

        left = QWidget()
        left_layout = QVBoxLayout(left)

        # 导航
        nav = QGroupBox("导航")
        nav_l = QHBoxLayout(nav)
        self.btn_nav_log = QPushButton("🧾 日志分析")
        self.btn_nav_reg = QPushButton("🧩 寄存器分析")
        self.btn_nav_log.setStyleSheet(self._btn_css("#2563EB", "#1D4ED8"))
        self.btn_nav_reg.setStyleSheet(self._btn_css("#6B7280", "#4B5563"))
        self.btn_nav_log.clicked.connect(lambda: self._switch_page(0))
        self.btn_nav_reg.clicked.connect(lambda: self._switch_page(1))
        nav_l.addWidget(self.btn_nav_log)
        nav_l.addWidget(self.btn_nav_reg)
        left_layout.addWidget(nav)

        self.left_stack = QStackedWidget()
        left_layout.addWidget(self.left_stack, 1)

        # 页面1：日志分析
        page_log = QWidget()
        p1 = QVBoxLayout(page_log)

        mode_group = QGroupBox("分析模式")
        mode_l = QHBoxLayout(mode_group)
        self.rb_healthd = QRadioButton("Healthd")
        self.rb_vbat = QRadioButton("Vbat")
        self.rb_healthd.setChecked(True)
        mode_btns = QButtonGroup(self)
        mode_btns.addButton(self.rb_healthd)
        mode_btns.addButton(self.rb_vbat)
        self.rb_healthd.toggled.connect(self._on_mode_changed)
        self.rb_vbat.toggled.connect(self._on_mode_changed)
        mode_l.addWidget(self.rb_healthd)
        mode_l.addWidget(self.rb_vbat)
        mode_l.addStretch(1)
        p1.addWidget(mode_group)

        export_group = QGroupBox("手机 LOG 导出分析")
        ex_l = QVBoxLayout(export_group)
        self.device_list = QListWidget()
        self.device_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        ex_l.addWidget(self.device_list)

        ex_row = QHBoxLayout()
        ex_row.addWidget(QLabel("导出目录"))
        self.export_dir_edit = QLineEdit("/tmp")
        btn_export_pick = QPushButton("...")
        btn_export_pick.clicked.connect(self._pick_export_dir)
        ex_row.addWidget(self.export_dir_edit, 1)
        ex_row.addWidget(btn_export_pick)
        ex_l.addLayout(ex_row)

        ex_btn_row = QHBoxLayout()
        self.btn_export = QPushButton("📦 导出并分析")
        self.btn_csv = QPushButton("📊 导出 CSV")
        self.btn_export.setStyleSheet(self._btn_css("#4B5563", "#374151"))
        self.btn_csv.setStyleSheet(self._btn_css("#6B7280", "#4B5563"))
        self.btn_export.clicked.connect(self._export_and_analyze)
        self.btn_csv.clicked.connect(self._export_csv)
        self.btn_csv.setEnabled(False)
        ex_btn_row.addWidget(self.btn_export)
        ex_btn_row.addWidget(self.btn_csv)
        ex_l.addLayout(ex_btn_row)
        p1.addWidget(export_group)

        local_group = QGroupBox("本地 LOG 分析")
        local_l = QVBoxLayout(local_group)
        self.local_path_edit = QLineEdit()
        self.local_path_edit.setPlaceholderText("拖放文件/文件夹，或点击 ... 选择")
        self.local_path_edit.setAcceptDrops(True)
        self.local_path_edit.installEventFilter(self)

        local_row = QHBoxLayout()
        local_row.addWidget(QLabel("本地路径"))
        local_row.addWidget(self.local_path_edit, 1)
        btn_local = QPushButton("...")
        btn_local.clicked.connect(self._show_local_menu)
        local_row.addWidget(btn_local)
        local_l.addLayout(local_row)

        local_btn_row = QHBoxLayout()
        self.btn_analyze = QPushButton("🔍 开始分析")
        self.btn_clear = QPushButton("🗑️ 清空")
        self.btn_analyze.setStyleSheet(self._btn_css("#16A34A", "#15803D"))
        self.btn_clear.setStyleSheet(self._btn_css("#DC2626", "#B91C1C"))
        self.btn_analyze.clicked.connect(self._start_local_analysis)
        self.btn_clear.clicked.connect(self._clear_all)
        local_btn_row.addWidget(self.btn_analyze)
        local_btn_row.addWidget(self.btn_clear)
        local_l.addLayout(local_btn_row)
        p1.addWidget(local_group)

        process_group = QGroupBox("运行日志")
        pg = QVBoxLayout(process_group)
        self.process_text = QTextEdit()
        self.process_text.setReadOnly(True)
        self.process_text.setFont(QFont("Consolas", 9))
        pg.addWidget(self.process_text)
        p1.addWidget(process_group, 1)

        # 页面2：寄存器分析
        page_reg = QWidget()
        p2 = QVBoxLayout(page_reg)

        reg_group = QGroupBox("寄存器分析（I2C）")
        reg_l = QVBoxLayout(reg_group)
        form = QFormLayout()
        self.reg_device_combo = QComboBox()
        self.i2c_bus_spin = QSpinBox(); self.i2c_bus_spin.setRange(0, 20); self.i2c_bus_spin.setValue(1)
        self.i2c_addr_edit = QLineEdit("0x6B")
        self.i2c_reg_edit = QLineEdit("0x10")
        self.i2c_val_edit = QLineEdit("0x00")
        form.addRow("设备", self.reg_device_combo)
        form.addRow("I2C Bus", self.i2c_bus_spin)
        form.addRow("从地址", self.i2c_addr_edit)
        form.addRow("寄存器", self.i2c_reg_edit)
        form.addRow("写入值", self.i2c_val_edit)
        reg_l.addLayout(form)

        reg_btns = QHBoxLayout()
        self.btn_i2c_read = QPushButton("📥 读寄存器")
        self.btn_i2c_write = QPushButton("📤 写寄存器")
        self.btn_i2c_dump = QPushButton("🧾 i2cDUMP")
        self.btn_i2c_read.setStyleSheet(self._btn_css("#2563EB", "#1D4ED8"))
        self.btn_i2c_write.setStyleSheet(self._btn_css("#16A34A", "#15803D"))
        self.btn_i2c_dump.setStyleSheet(self._btn_css("#7C3AED", "#6D28D9"))
        self.btn_i2c_read.clicked.connect(self.i2c_read_reg)
        self.btn_i2c_write.clicked.connect(self.i2c_write_reg)
        self.btn_i2c_dump.clicked.connect(self.i2c_dump_regs)
        reg_btns.addWidget(self.btn_i2c_read)
        reg_btns.addWidget(self.btn_i2c_write)
        reg_btns.addWidget(self.btn_i2c_dump)
        reg_l.addLayout(reg_btns)

        self.reg_process_text = QTextEdit()
        self.reg_process_text.setReadOnly(True)
        self.reg_process_text.setFont(QFont("Consolas", 9))
        reg_l.addWidget(self.reg_process_text)
        p2.addWidget(reg_group)

        self.left_stack.addWidget(page_log)
        self.left_stack.addWidget(page_reg)

        # 右侧结果区
        right = QWidget()
        right_layout = QVBoxLayout(right)
        self.result_table = QTreeWidget()
        self.result_table.setRootIsDecorated(False)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.setHeaderLabels(["请先进行分析"])
        right_layout.addWidget(self.result_table, 1)

        self.stats_label = QLabel("")
        self.stats_label.setStyleSheet("padding:8px;background:#EEF2FF;border:1px solid #C7D2FE;border-radius:6px;")
        right_layout.addWidget(self.stats_label)

        self.reg_detail_text = QTextEdit()
        self.reg_detail_text.setReadOnly(True)
        self.reg_detail_text.setFont(QFont("Consolas", 9))
        self.reg_detail_text.setPlaceholderText("寄存器操作详细结果显示在这里")
        right_layout.addWidget(self.reg_detail_text, 1)

        self.splitter.addWidget(left)
        self.splitter.addWidget(right)
        self.splitter.setSizes([520, 740])

    # -------- 公共行为 --------
    def _init_timers(self) -> None:
        self.log_timer = QTimer(self)
        self.log_timer.setInterval(120)
        self.log_timer.timeout.connect(self._flush_log)
        self.log_timer.start()

        self.reg_log_timer = QTimer(self)
        self.reg_log_timer.setInterval(100)
        self.reg_log_timer.timeout.connect(self._flush_reg_log)
        self.reg_log_timer.start()

        self.dev_timer = QTimer(self)
        self.dev_timer.setInterval(1200)
        self.dev_timer.timeout.connect(self._poll_devices_once)
        self.dev_timer.start()

    def _flush_log(self) -> None:
        if not self._log_queue:
            return
        text = "\n".join(self._log_queue) + "\n"
        self._log_queue.clear()
        self.process_text.moveCursor(QTextCursor.End)
        self.process_text.insertPlainText(text)
        self.process_text.verticalScrollBar().setValue(self.process_text.verticalScrollBar().maximum())

    def _flush_reg_log(self) -> None:
        if not self._reg_log_queue:
            return
        text = "\n".join(self._reg_log_queue) + "\n"
        self._reg_log_queue.clear()
        self.reg_process_text.moveCursor(QTextCursor.End)
        self.reg_process_text.insertPlainText(text)
        self.reg_process_text.verticalScrollBar().setValue(self.reg_process_text.verticalScrollBar().maximum())

    def log(self, msg: str) -> None:
        self._log_queue.append(msg.rstrip())

    def reg_log(self, msg: str) -> None:
        self._reg_log_queue.append(msg.rstrip())

    def _switch_page(self, idx: int) -> None:
        self.left_stack.setCurrentIndex(idx)
        active = ("#2563EB", "#1D4ED8")
        normal = ("#6B7280", "#4B5563")
        self.btn_nav_log.setStyleSheet(self._btn_css(*(active if idx == 0 else normal)))
        self.btn_nav_reg.setStyleSheet(self._btn_css(*(active if idx == 1 else normal)))

    def _set_main_busy(self, analysis: bool = False, export: bool = False, csv_busy: bool = False) -> None:
        self._busy_analysis, self._busy_export, self._busy_csv = analysis, export, csv_busy
        idle = not (analysis or export)
        self.btn_analyze.setEnabled(idle)
        self.btn_export.setEnabled(idle and self.device_list.count() > 0)
        self.btn_csv.setEnabled(bool(self.current_result) and not csv_busy)

    def _set_reg_busy(self, busy: bool) -> None:
        self._busy_reg = busy
        self.btn_i2c_read.setEnabled(not busy)
        self.btn_i2c_write.setEnabled(not busy)
        self.btn_i2c_dump.setEnabled(not busy)

    def _on_mode_changed(self, checked: bool) -> None:
        if checked:
            self.current_mode = "Healthd" if self.rb_healthd.isChecked() else "Vbat"
            self.log(f"[INFO] 切换模式：{self.current_mode}")

    def _poll_devices_once(self) -> None:
        try:
            self.adb.ensure_available()
            devs = self.adb.devices()
        except Exception as e:
            self.log(f"[WARN] 轮询设备失败：{e}")
            devs = []

        selected = {it.data(Qt.UserRole) for it in self.device_list.selectedItems()}

        self.device_list.clear()
        self.reg_device_combo.clear()
        for serial, desc in devs:
            text = f"{serial}  {desc}" if desc else serial
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, serial)
            self.device_list.addItem(item)
            if serial in selected:
                item.setSelected(True)
            self.reg_device_combo.addItem(text, serial)

        self.btn_export.setEnabled(bool(devs) and not self._busy_export)

    # -------- 文件路径选择 --------
    def _pick_export_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "选择导出目录", self.export_dir_edit.text().strip())
        if d:
            self.export_dir_edit.setText(d)

    def _show_local_menu(self) -> None:
        menu = QMenu(self)
        act_file = menu.addAction("选择文件")
        act_dir = menu.addAction("选择文件夹")
        action = menu.exec(self.sender().mapToGlobal(self.sender().rect().bottomLeft()))
        if action == act_file:
            self._pick_local_file()
        elif action == act_dir:
            self._pick_local_dir()

    def _pick_local_file(self) -> None:
        fp, _ = QFileDialog.getOpenFileName(self, "选择日志文件", "", "日志文件 (*.log *.txt *.out *.csv);;所有文件 (*.*)")
        if fp:
            self.local_path_edit.setText(fp)

    def _pick_local_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "选择日志文件夹", "")
        if d:
            self.local_path_edit.setText(d)

    def eventFilter(self, obj, event):
        if obj is self.local_path_edit and event.type() in (QEvent.DragEnter, QEvent.Drop):
            if event.type() == QEvent.DragEnter and event.mimeData().hasUrls():
                event.acceptProposedAction()
                return True
            if event.type() == QEvent.Drop:
                urls = event.mimeData().urls()
                if urls:
                    self.local_path_edit.setText(urls[0].toLocalFile())
                event.acceptProposedAction()
                return True
        return super().eventFilter(obj, event)

    # -------- 日志分析流程 --------
    def _start_local_analysis(self) -> None:
        if self._busy_analysis or self._busy_export:
            return
        p = Path(self.local_path_edit.text().strip())
        if not p.exists():
            QMessageBox.warning(self, "提示", "请选择有效的本地日志路径")
            return

        parser = self.parsers[self.current_mode]
        self._set_main_busy(analysis=True)
        self.worker_analysis = AnalysisWorker(self.analyzer, p, parser)
        self.worker_analysis.log_signal.connect(self.log)
        self.worker_analysis.result_signal.connect(self._display_result)
        self.worker_analysis.finished.connect(lambda: self._set_main_busy())
        self.worker_analysis.start()

    def _export_and_analyze(self) -> None:
        if self._busy_analysis or self._busy_export:
            return

        out_dir = Path(self.export_dir_edit.text().strip())
        if not out_dir.exists() or not out_dir.is_dir():
            QMessageBox.warning(self, "提示", "导出目录无效")
            return

        serials = [it.data(Qt.UserRole) for it in self.device_list.selectedItems() if it.data(Qt.UserRole)]
        if not serials and self.device_list.count() > 0:
            serials = [self.device_list.item(0).data(Qt.UserRole)]
        if not serials:
            QMessageBox.warning(self, "提示", "请先选择设备")
            return

        parser = self.parsers[self.current_mode]
        self._set_main_busy(export=True)
        self.worker_export = ExportAnalyzeWorker(self.adb, self.analyzer, serials, out_dir, parser)
        self.worker_export.log_signal.connect(self.log)
        self.worker_export.result_signal.connect(self._display_result)
        self.worker_export.finished.connect(lambda: self._set_main_busy())
        self.worker_export.start()

    def _display_result(self, result: ParseResult) -> None:
        self.current_result = result

        columns = list(result.columns)
        if "timestamp" in columns:
            columns.remove("timestamp")
        if "log_file" in columns:
            columns.remove("log_file")
            columns.append("log_file")

        self.result_table.clear()
        self.result_table.setColumnCount(len(columns))
        self.result_table.setHeaderLabels(columns)

        idx_map = [result.columns.index(c) if c in result.columns else -1 for c in columns]
        show_rows = min(MAX_UI_ROWS, result.parsed_rows)
        for r in result.rows[:show_rows]:
            values = [r[i] if 0 <= i < len(r) else "" for i in idx_map]
            item = QTreeWidgetItem(values)
            for ci, v in enumerate(values):
                item.setTextAlignment(ci, Qt.AlignCenter)
                if v.startswith("0x") or v.lstrip("-").isdigit():
                    item.setForeground(ci, QColor("#2563EB"))
            self.result_table.addTopLevelItem(item)

        self._autosize_table(columns)
        self.stats_label.setText(
            f"解析结果: {result.parsed_rows} 行 | 扫描文件: {result.files_scanned} | "
            f"扫描行数: {result.lines_scanned} | 匹配行数: {result.matched_lines} | UI显示: {show_rows}"
        )
        self.btn_csv.setEnabled(result.parsed_rows > 0)

    def _autosize_table(self, columns: List[str]) -> None:
        fm = QFontMetrics(self.result_table.font())
        header = self.result_table.header()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setDefaultAlignment(Qt.AlignCenter)

        for ci, name in enumerate(columns):
            width = max(60, fm.horizontalAdvance(name) + 22)
            for r in range(min(200, self.result_table.topLevelItemCount())):
                text = self.result_table.topLevelItem(r).text(ci)
                width = max(width, fm.horizontalAdvance(text[:24]) + 20)
            self.result_table.setColumnWidth(ci, min(230, width))

    def _export_csv(self) -> None:
        if self._busy_csv or not self.current_result:
            return
        if not self.current_result.rows:
            QMessageBox.information(self, "提示", "没有可导出的结果")
            return

        cols = list(self.current_result.columns)
        if "timestamp" in cols:
            cols.remove("timestamp")
        if "log_file" in cols:
            cols.remove("log_file")
            cols.append("log_file")

        idx_map = [self.current_result.columns.index(c) for c in cols]
        rows = [tuple(row[i] for i in idx_map) for row in self.current_result.rows]

        default_name = f"电池日志分析_{self.current_mode}_{dt.datetime.now():%Y%m%d_%H%M%S}.csv"
        fp, _ = QFileDialog.getSaveFileName(self, "导出 CSV", default_name, "CSV文件 (*.csv)")
        if not fp:
            return

        self._set_main_busy(csv_busy=True)
        self.worker_csv = CsvExportWorker(fp, cols, rows)
        self.worker_csv.done_signal.connect(self._on_csv_done)
        self.worker_csv.start()

    def _on_csv_done(self, ok: bool, msg: str) -> None:
        self._set_main_busy(csv_busy=False)
        if ok:
            self.log(f"[OK] CSV 导出完成：{msg}")
            QMessageBox.information(self, "导出成功", f"CSV 已导出：\n{msg}")
        else:
            self.log(f"[ERROR] CSV 导出失败：{msg}")
            QMessageBox.critical(self, "导出失败", msg)

    # -------- 寄存器流程 --------
    def _selected_reg_serial(self) -> str:
        return self.reg_device_combo.currentData() or ""

    @staticmethod
    def _fmt_cmd_detail(serial: str, cmd: str, rc: int, out: str, err: str) -> str:
        return (
            f"serial: {serial}\n"
            f"cmd   : {cmd}\n"
            f"rc    : {rc}\n\n"
            f"stdout:\n{(out or '').strip() or '(empty)'}\n\n"
            f"stderr:\n{(err or '').strip() or '(empty)'}\n"
        )

    def _run_reg_shell(self, cmd: str, timeout: int, done_cb: Callable[[int, str, str], None]) -> None:
        serial = self._selected_reg_serial()
        if not serial:
            self.reg_log("[WARN] 未选择设备")
            self._set_reg_busy(False)
            return
        self.reg_worker = ShellCmdWorker(self.adb, serial, cmd, timeout=timeout, auto_root=True)
        self.reg_worker.done_signal.connect(done_cb)
        self.reg_worker.start()

    def i2c_read_reg(self) -> None:
        if self._busy_reg:
            return
        serial = self._selected_reg_serial()
        if not serial:
            self.reg_log("[WARN] 未选择设备")
            return

        bus = self.i2c_bus_spin.value()
        addr = self.i2c_addr_edit.text().strip()
        reg = self.i2c_reg_edit.text().strip()
        cmd = self.i2c_service.cmd_read(bus, addr, reg)

        self._set_reg_busy(True)
        self.reg_log(f"[STEP] 读取寄存器：{cmd}")

        def _done(rc: int, out: str, err: str) -> None:
            try:
                detail = self._fmt_cmd_detail(serial, cmd, rc, out, err)
                if rc != 0:
                    self.reg_log(f"[ERROR] 读失败 rc={rc}")
                    self.reg_detail_text.setPlainText("I2C READ - FAIL\n\n" + detail)
                    return
                try:
                    v = self.i2c_service.parse_i2cget_output(out)
                    self.reg_log(f"[OK] value=0x{v:02X} ({v})")
                    self.reg_detail_text.setPlainText(
                        f"I2C READ - OK\n\nvalue_hex: 0x{v:02X}\nvalue_dec: {v}\n\n" + detail
                    )
                except Exception as pe:
                    self.reg_log(f"[WARN] 输出解析失败：{pe}")
                    self.reg_detail_text.setPlainText("I2C READ - PARSE WARN\n\n" + detail)
            finally:
                self._set_reg_busy(False)

        self._run_reg_shell(cmd, timeout=8, done_cb=_done)

    def i2c_write_reg(self) -> None:
        if self._busy_reg:
            return
        serial = self._selected_reg_serial()
        if not serial:
            self.reg_log("[WARN] 未选择设备")
            return

        bus = self.i2c_bus_spin.value()
        addr = self.i2c_addr_edit.text().strip()
        reg = self.i2c_reg_edit.text().strip()
        val = self.i2c_val_edit.text().strip()

        cmd_read = self.i2c_service.cmd_read(bus, addr, reg)
        cmd_write = self.i2c_service.cmd_write(bus, addr, reg, val)

        self._set_reg_busy(True)
        self.reg_log(f"[STEP] 写寄存器：{cmd_write}")

        ctx: Dict[str, Optional[int]] = {"before": None, "after": None}
        raw: Dict[str, str] = {"before": "", "after": ""}

        def step_read_after() -> None:
            self.reg_log(f"[STEP] 写后读取：{cmd_read}")

            def _done_after(rc: int, out: str, err: str) -> None:
                try:
                    if rc != 0:
                        self.reg_log(f"[ERROR] 写后读取失败 rc={rc}")
                        self.reg_detail_text.setPlainText("I2C WRITE - FAIL(after)\n\n" + self._fmt_cmd_detail(serial, cmd_read, rc, out, err))
                        return
                    raw["after"] = out
                    ctx["after"] = self.i2c_service.parse_i2cget_output(out)
                    changed = ctx["before"] != ctx["after"]
                    self.reg_log(f"[OK] before=0x{ctx['before']:02X} after=0x{ctx['after']:02X} changed={changed}")
                    self.reg_detail_text.setPlainText(
                        "I2C WRITE - OK\n\n"
                        f"write_val: {val}\n"
                        f"before  : 0x{ctx['before']:02X} ({ctx['before']})\n"
                        f"after   : 0x{ctx['after']:02X} ({ctx['after']})\n"
                        f"changed : {'YES' if changed else 'NO'}\n\n"
                        "-- BEFORE RAW --\n"
                        + raw["before"].strip() + "\n\n"
                        "-- AFTER RAW --\n"
                        + raw["after"].strip() + "\n"
                    )
                except Exception as e:
                    self.reg_log(f"[WARN] 写后解析失败：{e}")
                    self.reg_detail_text.setPlainText("I2C WRITE - PARSE WARN\n\n" + self._fmt_cmd_detail(serial, cmd_read, rc, out, err))
                finally:
                    self._set_reg_busy(False)

            self._run_reg_shell(cmd_read, timeout=8, done_cb=_done_after)

        def step_write() -> None:
            self.reg_log(f"[STEP] 执行写入：{cmd_write}")

            def _done_write(rc: int, out: str, err: str) -> None:
                if rc != 0:
                    self.reg_log(f"[ERROR] 写入失败 rc={rc}")
                    self.reg_detail_text.setPlainText("I2C WRITE - FAIL(write)\n\n" + self._fmt_cmd_detail(serial, cmd_write, rc, out, err))
                    self._set_reg_busy(False)
                    return
                self.reg_log("[OK] 写入成功")
                step_read_after()

            self._run_reg_shell(cmd_write, timeout=8, done_cb=_done_write)

        self.reg_log(f"[STEP] 写前读取：{cmd_read}")

        def _done_before(rc: int, out: str, err: str) -> None:
            if rc != 0:
                self.reg_log(f"[ERROR] 写前读取失败 rc={rc}")
                self.reg_detail_text.setPlainText("I2C WRITE - FAIL(before)\n\n" + self._fmt_cmd_detail(serial, cmd_read, rc, out, err))
                self._set_reg_busy(False)
                return
            try:
                raw["before"] = out
                ctx["before"] = self.i2c_service.parse_i2cget_output(out)
                self.reg_log(f"[OK] before=0x{ctx['before']:02X} ({ctx['before']})")
                step_write()
            except Exception as e:
                self.reg_log(f"[WARN] 写前解析失败：{e}")
                self.reg_detail_text.setPlainText("I2C WRITE - PARSE WARN(before)\n\n" + self._fmt_cmd_detail(serial, cmd_read, rc, out, err))
                self._set_reg_busy(False)

        self._run_reg_shell(cmd_read, timeout=8, done_cb=_done_before)

    def i2c_dump_regs(self) -> None:
        if self._busy_reg:
            return
        serial = self._selected_reg_serial()
        if not serial:
            self.reg_log("[WARN] 未选择设备")
            return

        bus = self.i2c_bus_spin.value()
        addr = self.i2c_addr_edit.text().strip()
        cmd = self.i2c_service.cmd_dump(bus, addr)

        self._set_reg_busy(True)
        self.reg_log(f"[STEP] 执行 dump：{cmd}")

        def _done(rc: int, out: str, err: str) -> None:
            try:
                detail = self._fmt_cmd_detail(serial, cmd, rc, out, err)
                if rc != 0:
                    self.reg_log(f"[ERROR] dump 失败 rc={rc}")
                    self.reg_detail_text.setPlainText("I2C DUMP - FAIL\n\n" + detail)
                    return
                table = self.i2c_service.extract_dump_table(out)
                self.reg_log("[OK] dump 完成")
                self.reg_detail_text.setPlainText(
                    f"I2C DUMP - OK\n\nbus={bus} addr={addr}\n\nParsed:\n{table}\n\nRaw:\n{detail}"
                )
            finally:
                self._set_reg_busy(False)

        self._run_reg_shell(cmd, timeout=12, done_cb=_done)

    # -------- 清理与关闭 --------
    def _clear_all(self) -> None:
        self.current_result = None
        self.local_path_edit.clear()
        self.result_table.clear()
        self.result_table.setHeaderLabels(["请先进行分析"])
        self.stats_label.setText("")
        self.process_text.clear()
        self.reg_process_text.clear()
        self.reg_detail_text.clear()
        self.btn_csv.setEnabled(False)

    def closeEvent(self, event) -> None:
        for name in ("worker_analysis", "worker_export", "worker_csv", "reg_worker"):
            w = getattr(self, name, None)
            if w and w.isRunning():
                w.requestInterruption()
                w.wait(300)
        event.accept()


# ========================= 程序入口 =========================
def main() -> None:
    if sys.platform.startswith("win"):
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("wph.autochargelog.acl.v1.optimized")
        except Exception:
            pass

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    try:
        app.setWindowIcon(QIcon("A_256x256_ICO_format_digital_icon_features_a_charg.ico"))
    except Exception:
        pass

    window = ChargeAutoTool()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
