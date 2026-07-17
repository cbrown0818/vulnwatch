#!/usr/bin/env python3
"""MOV Mobile IT desktop interface for VulnWatch."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


APP_NAME = "MOV Mobile IT — VulnWatch"
BG = "#071014"
PANEL = "#0D1C21"
PANEL_2 = "#11272D"
TEAL = "#20D6C7"
TEAL_DARK = "#0B827C"
TEXT = "#ECFAF8"
MUTED = "#8EAAA8"
RED = "#FF6577"
BORDER = "#1C3D42"


def default_report_root() -> Path:
    return Path.home() / "Documents" / "MOV Mobile IT" / "VulnWatch Reports"


def settings_path() -> Path:
    base = Path(os.getenv("APPDATA", Path.home())) / "MOV Mobile IT" / "VulnWatch"
    return base / "settings.json"


class CircuitLogo(tk.Canvas):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, width=74, height=74, bg=BG, highlightthickness=0)
        self.create_oval(12, 12, 62, 62, outline=TEAL, width=2)
        self.create_arc(23, 20, 50, 56, start=80, extent=210, style="arc", outline=TEAL, width=2)
        self.create_line(36, 19, 36, 55, fill=TEAL, width=2)
        for x1, y1, x2, y2 in ((12, 36, 2, 36), (62, 36, 72, 36), (36, 12, 36, 2),
                               (20, 18, 11, 9), (54, 54, 64, 64)):
            self.create_line(x1, y1, x2, y2, fill=TEAL, width=2)
            self.create_oval(x2 - 2, y2 - 2, x2 + 2, y2 + 2, fill=TEAL, outline="")


class VulnWatchGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1040x720")
        self.minsize(880, 640)
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.process: subprocess.Popen[str] | None = None
        self.messages: queue.Queue[tuple[str, str | int]] = queue.Queue()
        self.last_report: Path | None = None

        self.days = tk.StringVar(value="120")
        self.limit = tk.StringVar(value="100")
        self.scope = tk.StringVar(value="Top 100 overall")
        self.output_root = tk.StringVar(value=str(default_report_root()))
        self.api_key = tk.StringVar()
        self.status = tk.StringVar(value="READY TO SCAN")
        self.summary = tk.StringVar(value="Current defensive intelligence for Windows, macOS, Linux, Android, and iOS/iPadOS")

        self._configure_styles()
        self._load_settings()
        self._build()
        self.after(100, self._drain_messages)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("MOV.TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("MOV.TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Segoe UI Semibold", 24))
        style.configure("Sub.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Head.TLabel", background=PANEL, foreground=TEAL, font=("Segoe UI Semibold", 11))
        style.configure("Status.TLabel", background=PANEL_2, foreground=TEAL, font=("Segoe UI Semibold", 10))
        style.configure("MOV.TEntry", fieldbackground=PANEL_2, foreground=TEXT, insertcolor=TEXT,
                        bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER, padding=8)
        style.configure("MOV.TCombobox", fieldbackground=PANEL_2, foreground=TEXT, arrowcolor=TEAL,
                        bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER, padding=7)
        style.map("MOV.TCombobox", fieldbackground=[("readonly", PANEL_2)], foreground=[("readonly", TEXT)])
        style.configure("Teal.TButton", background=TEAL, foreground="#03201E", borderwidth=0,
                        font=("Segoe UI Semibold", 10), padding=(18, 10))
        style.map("Teal.TButton", background=[("active", "#56E8DC"), ("disabled", TEAL_DARK)])
        style.configure("Ghost.TButton", background=PANEL_2, foreground=TEXT, bordercolor=BORDER,
                        font=("Segoe UI", 10), padding=(14, 9))
        style.map("Ghost.TButton", background=[("active", "#18383E")])
        style.configure("MOV.Horizontal.TProgressbar", background=TEAL, troughcolor=PANEL_2,
                        bordercolor=PANEL_2, lightcolor=TEAL, darkcolor=TEAL)

    def _build(self) -> None:
        shell = ttk.Frame(self, style="MOV.TFrame", padding=(30, 22))
        shell.pack(fill="both", expand=True)

        header = ttk.Frame(shell, style="MOV.TFrame")
        header.pack(fill="x", pady=(0, 18))
        CircuitLogo(header).pack(side="left", padx=(0, 14))
        names = ttk.Frame(header, style="MOV.TFrame")
        names.pack(side="left", fill="x", expand=True)
        ttk.Label(names, text="MOV MOBILE IT", style="Sub.TLabel").pack(anchor="w")
        ttk.Label(names, text="VulnWatch", style="Title.TLabel").pack(anchor="w")
        ttk.Label(names, textvariable=self.summary, style="Sub.TLabel").pack(anchor="w", pady=(3, 0))
        status_box = ttk.Label(header, textvariable=self.status, style="Status.TLabel", padding=(14, 8))
        status_box.pack(side="right")

        body = ttk.Frame(shell, style="MOV.TFrame")
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        controls = ttk.Frame(body, style="Panel.TFrame", padding=22)
        controls.grid(row=0, column=0, sticky="nsw", padx=(0, 16))
        ttk.Label(controls, text="SCAN CONFIGURATION", style="Head.TLabel").pack(anchor="w", pady=(0, 17))
        self._field(controls, "Publication lookback", self.days, values=("30", "60", "90", "120", "365", "730"))
        self._field(controls, "Results per scope", self.limit, values=("25", "50", "100", "250", "500"))
        self._field(controls, "Report scope", self.scope, values=("Top 100 overall", "Up to limit per platform"))

        ttk.Label(controls, text="Report folder", style="Panel.TLabel").pack(anchor="w", pady=(11, 5))
        path_row = ttk.Frame(controls, style="Panel.TFrame")
        path_row.pack(fill="x")
        ttk.Entry(path_row, textvariable=self.output_root, style="MOV.TEntry", width=29).pack(side="left", fill="x", expand=True)
        ttk.Button(path_row, text="…", style="Ghost.TButton", width=3, command=self.choose_folder).pack(side="left", padx=(6, 0))

        ttk.Label(controls, text="NVD API key (recommended)", style="Panel.TLabel").pack(anchor="w", pady=(15, 5))
        ttk.Entry(controls, textvariable=self.api_key, show="•", style="MOV.TEntry").pack(fill="x")
        ttk.Label(controls, text="Stored only on this computer.", style="Panel.TLabel", foreground=MUTED).pack(anchor="w", pady=(4, 18))

        self.scan_button = ttk.Button(controls, text="RUN VULNERABILITY SCAN", style="Teal.TButton", command=self.start_scan)
        self.scan_button.pack(fill="x", pady=(6, 8))
        self.cancel_button = ttk.Button(controls, text="Cancel scan", style="Ghost.TButton", command=self.cancel_scan, state="disabled")
        self.cancel_button.pack(fill="x")

        activity = ttk.Frame(body, style="Panel.TFrame", padding=22)
        activity.grid(row=0, column=1, sticky="nsew")
        activity.columnconfigure(0, weight=1)
        activity.rowconfigure(3, weight=1)
        top = ttk.Frame(activity, style="Panel.TFrame")
        top.grid(row=0, column=0, sticky="ew")
        ttk.Label(top, text="SCAN ACTIVITY", style="Head.TLabel").pack(side="left")
        self.open_button = ttk.Button(top, text="Open latest report", style="Ghost.TButton", command=self.open_report, state="disabled")
        self.open_button.pack(side="right")
        self.progress = ttk.Progressbar(activity, style="MOV.Horizontal.TProgressbar", mode="indeterminate")
        self.progress.grid(row=1, column=0, sticky="ew", pady=(18, 10))
        self.stage_label = ttk.Label(activity, text="Waiting for a scan.", style="Panel.TLabel")
        self.stage_label.grid(row=2, column=0, sticky="w", pady=(0, 10))

        log_frame = tk.Frame(activity, bg=PANEL_2, highlightbackground=BORDER, highlightthickness=1)
        log_frame.grid(row=3, column=0, sticky="nsew")
        self.log = tk.Text(log_frame, bg=PANEL_2, fg=MUTED, insertbackground=TEXT, relief="flat",
                           font=("Cascadia Mono", 9), padx=12, pady=12, wrap="word", state="disabled")
        scroll = ttk.Scrollbar(log_frame, command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        self.log.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._log("VulnWatch is ready. Configure the scan and select Run Vulnerability Scan.")

        footer = ttk.Label(shell, text="DEFENSIVE SECURITY INTELLIGENCE  •  MOV MOBILE IT", style="Sub.TLabel")
        footer.pack(anchor="e", pady=(14, 0))

    def _field(self, parent: ttk.Frame, label: str, variable: tk.StringVar, values: tuple[str, ...]) -> None:
        ttk.Label(parent, text=label, style="Panel.TLabel").pack(anchor="w", pady=(10, 5))
        ttk.Combobox(parent, textvariable=variable, values=values, state="readonly", style="MOV.TCombobox").pack(fill="x")

    def _log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", f"[{datetime.now():%H:%M:%S}]  {text}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def choose_folder(self) -> None:
        selected = filedialog.askdirectory(initialdir=self.output_root.get() or str(Path.home()))
        if selected:
            self.output_root.set(selected)

    def start_scan(self) -> None:
        try:
            days, limit = int(self.days.get()), int(self.limit.get())
            if not 1 <= days <= 730 or not 1 <= limit <= 1000:
                raise ValueError
        except ValueError:
            messagebox.showerror(APP_NAME, "Lookback must be 1–730 days and result limit must be 1–1000.")
            return
        script = Path(__file__).with_name("vulnwatch.py")
        if not script.exists():
            messagebox.showerror(APP_NAME, f"The scraper engine was not found:\n{script}")
            return
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.last_report = Path(self.output_root.get()).expanduser() / stamp
        command = [sys.executable, "-u", str(script), "--days", str(days), "--limit", str(limit),
                   "--output", str(self.last_report)]
        if self.scope.get().startswith("Up to"):
            command.append("--per-platform")
        if self.api_key.get().strip():
            command.extend(("--nvd-api-key", self.api_key.get().strip()))

        self._save_settings()
        self.status.set("SCANNING")
        self.stage_label.configure(text="Connecting to authoritative vulnerability feeds…")
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.open_button.configure(state="disabled")
        self.progress.start(12)
        self._log(f"Started scan: {days}-day lookback, limit {limit}.")
        threading.Thread(target=self._run_process, args=(command,), daemon=True).start()

    def _run_process(self, command: list[str]) -> None:
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            text=True, bufsize=1, creationflags=flags)
            assert self.process.stdout is not None
            for line in self.process.stdout:
                clean = line.strip()
                if clean:
                    self.messages.put(("log", clean))
            code = self.process.wait()
            self.messages.put(("done", code))
        except Exception as exc:
            self.messages.put(("error", str(exc)))

    def _drain_messages(self) -> None:
        try:
            while True:
                kind, value = self.messages.get_nowait()
                if kind == "log":
                    text = str(value)
                    self._log(text)
                    self.stage_label.configure(text=text)
                elif kind == "done":
                    self._finish(int(value))
                else:
                    self._log(f"Application error: {value}")
                    self._finish(1)
        except queue.Empty:
            pass
        self.after(100, self._drain_messages)

    def _finish(self, code: int) -> None:
        self.process = None
        self.progress.stop()
        self.scan_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        report_exists = bool(self.last_report and (self.last_report / "index.html").exists())
        if code == 0 and report_exists:
            self.status.set("REPORT READY")
            self.stage_label.configure(text="Scan complete. Your interactive report is ready.")
            self.open_button.configure(state="normal")
            self._log(f"Report saved to {self.last_report}")
        elif code < 0:
            self.status.set("CANCELLED")
            self.stage_label.configure(text="Scan cancelled.")
        else:
            self.status.set("SCAN FAILED")
            self.stage_label.configure(text="The scan did not complete. Review the activity log.")

    def cancel_scan(self) -> None:
        if self.process and self.process.poll() is None:
            self._log("Cancelling scan…")
            self.process.terminate()

    def open_report(self) -> None:
        report = self.last_report / "index.html" if self.last_report else None
        if report and report.exists():
            webbrowser.open(report.resolve().as_uri())
        else:
            messagebox.showinfo(APP_NAME, "Run a successful scan first.")

    def _load_settings(self) -> None:
        try:
            data = json.loads(settings_path().read_text(encoding="utf-8"))
            self.days.set(str(data.get("days", self.days.get())))
            self.limit.set(str(data.get("limit", self.limit.get())))
            self.scope.set(data.get("scope", self.scope.get()))
            self.output_root.set(data.get("output_root", self.output_root.get()))
            self.api_key.set(data.get("api_key", ""))
        except (OSError, ValueError, TypeError):
            pass

    def _save_settings(self) -> None:
        path = settings_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"days": self.days.get(), "limit": self.limit.get(),
                                        "scope": self.scope.get(), "output_root": self.output_root.get(),
                                        "api_key": self.api_key.get()}), encoding="utf-8")
        except OSError:
            pass

    def on_close(self) -> None:
        if self.process and self.process.poll() is None:
            if not messagebox.askyesno(APP_NAME, "A scan is running. Cancel it and exit?"):
                return
            self.process.terminate()
        self._save_settings()
        self.destroy()


if __name__ == "__main__":
    VulnWatchGUI().mainloop()
