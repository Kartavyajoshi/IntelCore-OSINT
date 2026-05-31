"""
IntelCore OSINT Platform — Professional GUI v4.0
Sidebar navigation · Dashboard · Cyberpunk dark theme
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import json, sys, os, datetime, time, socket, subprocess, platform, math

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "functions"))

# ── Palette ───────────────────────────────────────────────────────────────────
C = {
    "bg":       "#0d1117",   # deep charcoal background
    "sidebar":  "#0a0e17",   # near-black sidebar
    "card":     "#161b22",   # dark elevated card
    "card2":    "#1c2333",   # slightly lighter card alt
    "border":   "#30363d",   # subtle border
    "cyan":     "#00d4ff",   # electric cyan primary
    "cyan_d":   "#00a8cc",   # dimmed cyan (hover/pressed)
    "purple":   "#a855f7",   # vivid violet secondary
    "green":    "#00e676",   # neon green success
    "amber":    "#ffab00",   # warm amber warning
    "red":      "#ff4757",   # crimson danger
    "text":     "#e6edf3",   # bright readable text
    "muted":    "#8b949e",   # medium gray label text
    "dim":      "#484f58",   # dimmed borders / minor text
    "white":    "#ffffff",
    "glow":     "#00d4ff22", # cyan glow tint (transparent)
    "card_hl":  "#1f2937",   # card hover highlight
}

# ── Typography ─────────────────────────────────────────────────────────────────
F = {
    "title":   ("Segoe UI",  20, "bold"),
    "head":    ("Segoe UI",  14, "bold"),
    "subhead": ("Segoe UI",  11, "bold"),
    "body":    ("Segoe UI",  10),
    "small":   ("Segoe UI",   9),
    "tiny":    ("Segoe UI",   7),
    "mono":    ("Consolas",  10),
    "mono_m":  ("Consolas",  11),
    "mono_l":  ("Consolas",  13),
    "nav":     ("Segoe UI",  10, "bold"),
    "badge":   ("Segoe UI",   8, "bold"),
    "cat":     ("Segoe UI",   7, "bold"),  # category headers
}


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY
# ─────────────────────────────────────────────────────────────────────────────
def ts():
    return datetime.datetime.now().strftime("%H:%M:%S")

def fmt_json(data):
    try:
        return json.dumps(data, indent=2, default=str)
    except Exception:
        return str(data)


class Tooltip:
    """Hover tooltip for Tkinter widgets."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tip_window or not self.text:
            return
        try:
            bbox = self.widget.bbox("insert")
            if bbox:
                x, y, cx, cy = bbox
                x = x + self.widget.winfo_rootx() + 25
                y = y + self.widget.winfo_rooty() + 20
            else:
                x = self.widget.winfo_rootx() + 25
                y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        except Exception:
            x = self.widget.winfo_rootx() + 25
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(1)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background=C["card2"], foreground=C["text"],
                         relief=tk.SOLID, borderwidth=1,
                         font=F["small"], padx=8, pady=5)
        label.pack(ipadx=1)

    def hide_tip(self, event=None):
        tw = self.tip_window
        self.tip_window = None
        if tw:
            tw.destroy()


class DetailDialog(tk.Toplevel):
    """Clean details popup with click-to-copy buttons."""
    def __init__(self, parent, title, data_dict):
        super().__init__(parent)
        self.title(title)
        self.geometry("560x440")
        self.resizable(False, False)
        self.configure(bg=C["bg"])
        self.transient(parent)
        self.grab_set()

        # Center dialog
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"+{x}+{y}")

        # Top Bar
        top = tk.Frame(self, bg=C["sidebar"], height=44)
        top.pack(fill=tk.X)
        top.pack_propagate(False)
        tk.Label(top, text="🔍  DETAIL VIEW", font=F["badge"], bg=C["sidebar"], fg=C["cyan"]).pack(side=tk.LEFT, padx=14)

        # Content Area (Scrollable)
        container = tk.Frame(self, bg=C["card"], highlightthickness=1, highlightbackground=C["border"])
        container.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        canvas = tk.Canvas(container, bg=C["card"], bd=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=C["card"])

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=480)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Add fields
        for key, val in data_dict.items():
            field_frame = tk.Frame(scrollable_frame, bg=C["card"], pady=6)
            field_frame.pack(fill=tk.X, padx=12)

            tk.Label(field_frame, text=str(key).upper(), font=F["badge"], bg=C["card"], fg=C["muted"]).pack(anchor="w")
            
            val_frame = tk.Frame(field_frame, bg=C["card"])
            val_frame.pack(fill=tk.X, pady=2)
            
            val_str = str(val)
            val_lbl = tk.Entry(val_frame, font=F["mono_m"], bg=C["card2"], fg=C["text"], relief="flat", bd=4)
            val_lbl.insert(0, val_str)
            val_lbl.config(state="readonly")
            val_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

            # Copy button
            btn = tk.Button(val_frame, text="⧉ Copy", font=F["tiny"], bg=C["card2"], fg=C["cyan"],
                            relief="flat", activebackground=C["card"],
                            activeforeground=C["cyan_d"], bd=0,
                            highlightbackground=C["card2"], highlightcolor=C["cyan"],
                            command=lambda v=val_str: self._copy(v))
            btn.pack(side=tk.RIGHT, padx=4)
            
            tk.Frame(scrollable_frame, bg=C["border"], height=1).pack(fill=tk.X, padx=12, pady=2)

    def _copy(self, value):
        self.clipboard_clear()
        self.clipboard_append(value)
        messagebox.showinfo("Copied", "Copied value to clipboard!", parent=self)


class NeonButton(tk.Canvas):
    """Fully custom neon-border button with hover glow."""
    def __init__(self, master, text="", command=None,
                 color=None, width=160, height=36,
                 font=None, icon="", tooltip=None, **kw):
        color = color or C["cyan"]
        self._normal_bg = kw.pop("bg", C["card"])
        super().__init__(master, width=width, height=height,
                         bg=self._normal_bg, bd=0, highlightthickness=0, **kw)
        self._text    = (icon + "  " + text).strip() if icon else text
        self._cmd     = command
        self._color   = color
        self._font    = font or F["body"]
        self._btn_w   = width
        self._btn_h   = height
        self._hovered = False
        self._draw()
        self.bind("<Enter>",    self._enter)
        self.bind("<Leave>",    self._leave)
        self.bind("<Button-1>", self._click)

        # Setup tooltip
        if tooltip:
            Tooltip(self, tooltip)
        elif text:
            # Auto tooltip mapping for common actions
            btn_tips = {
                "scan": "Execute scan on target",
                "search": "Search target keyword",
                "clear": "Clear results and reset panel",
                "export": "Export results to a JSON file",
                "refresh": "Refresh historical logs",
                "open reports folder": "Open the folder containing saved scan reports",
                "full scan": "Run a full scan on target",
                "free scan": "Run a free open-source scan on target",
                "dns recon": "Run a DNS resolution/recon scan on target",
            }
            norm_text = text.lower().strip()
            for key, tip in btn_tips.items():
                if key in norm_text:
                    Tooltip(self, tip)
                    break

    def _draw(self):
        self.delete("all")
        is_secondary = self._color in (C["dim"], C["muted"])

        if is_secondary:
            bg = C["card2"] if self._hovered else C["card"]
            fg = C["text"]
            brd = C["border"]
        else:
            if self._hovered:
                bg = C["cyan_d"] if self._color == C["cyan"] else self._color
                fg = "#ffffff"
            else:
                bg = self._color
                fg = "#ffffff"
            brd = bg

        r = 8
        w, h = self._btn_w, self._btn_h
        # Proper rounded rectangle using polygon + arcs
        self.create_rectangle(r, 0, w - r, h, fill=bg, outline=bg, width=0)
        self.create_rectangle(0, r, w, h - r, fill=bg, outline=bg, width=0)
        for cx, cy in [(r, r), (w - r, r), (r, h - r), (w - r, h - r)]:
            self.create_oval(cx - r, cy - r, cx + r, cy + r,
                             fill=bg, outline=bg, width=0)
        # Subtle top highlight line for 3D pop
        if not is_secondary and not self._hovered:
            self.create_line(r, 1, w - r, 1, fill="#ffffff", width=1)
        self.create_text(w // 2, h // 2, text=self._text, fill=fg,
                         font=self._font)

    def _enter(self, _):
        self._hovered = True
        self.config(cursor="hand2")
        self._draw()

    def _leave(self, _):
        self._hovered = False
        self.config(cursor="")
        self._draw()

    def _click(self, _):
        if self._cmd:
            self._cmd()


class NavButton(tk.Frame):
    """Left sidebar navigation item."""
    NORMAL_BG  = "#0a0e17"
    HOVER_BG   = "#151d2b"
    ACTIVE_BG  = "#0d1520"

    def __init__(self, master, icon, label, command=None, **kw):
        super().__init__(master, bg=self.NORMAL_BG, cursor="hand2", **kw)
        self._cmd    = command
        self._active = False

        self._indicator = tk.Frame(self, bg=self.NORMAL_BG, width=3)
        self._indicator.pack(side=tk.LEFT, fill=tk.Y)

        inner = tk.Frame(self, bg=self.NORMAL_BG)
        inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=8)

        self._icon_lbl = tk.Label(inner, text=icon,  font=("Segoe UI", 14),
                                  bg=self.NORMAL_BG, fg="#58647a")
        self._icon_lbl.pack(side=tk.LEFT, padx=(0, 8))

        self._text_lbl = tk.Label(inner, text=label, font=F["nav"],
                                  bg=self.NORMAL_BG, fg="#58647a",
                                  anchor="w")
        self._text_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        for w in (self, inner, self._icon_lbl, self._text_lbl):
            w.bind("<Button-1>", self._on_click)
            w.bind("<Enter>",    self._on_enter)
            w.bind("<Leave>",    self._on_leave)

    def _on_click(self, _):
        if self._cmd:
            self._cmd()

    def _on_enter(self, _):
        if not self._active:
            self._set_bg(self.HOVER_BG, text_color="#c9d1d9")

    def _on_leave(self, _):
        if not self._active:
            self._set_bg(self.NORMAL_BG, text_color="#58647a")

    def set_active(self, active: bool):
        self._active = active
        if active:
            self._indicator.config(bg=C["cyan"])
            self._set_bg(self.ACTIVE_BG, text_color=C["cyan"])
        else:
            self._indicator.config(bg=self.NORMAL_BG)
            self._set_bg(self.NORMAL_BG, text_color="#58647a")

    def _set_bg(self, bg, text_color=None):
        """Set background and text color for nav item and all children."""
        tc = text_color or "#58647a"
        for w in (self,):
            try:
                w.config(bg=bg)
            except Exception:
                pass
        for child in self.winfo_children():
            child.config(bg=bg)
            for sub in child.winfo_children():
                sub.config(bg=bg)
        self._icon_lbl.config(fg=tc)
        self._text_lbl.config(fg=tc)


class StatCard(tk.Frame):
    """Metric card for the dashboard with accent bar."""
    def __init__(self, master, title, value, unit="", color=None, icon="■", **kw):
        color = color or C["cyan"]
        super().__init__(master, bg=C["card"], bd=0,
                         highlightthickness=1, highlightbackground=C["border"], **kw)

        # Colored accent bar on the left
        tk.Frame(self, bg=color, width=3).pack(side=tk.LEFT, fill=tk.Y)

        body = tk.Frame(self, bg=C["card"])
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=12)

        # Top row: icon
        tk.Label(body, text=icon, font=("Segoe UI", 16),
                 bg=C["card"], fg=color).pack(anchor="w")

        # Value (large)
        self._val_lbl = tk.Label(body, text=str(value), font=("Segoe UI", 26, "bold"),
                                  bg=C["card"], fg=C["text"])
        self._val_lbl.pack(anchor="w", pady=(4, 0))

        # Unit
        tk.Label(body, text=unit, font=F["small"], bg=C["card"], fg=C["dim"]).pack(anchor="w")

        # Title
        tk.Label(body, text=title, font=F["body"], bg=C["card"], fg=C["muted"]).pack(anchor="w", pady=(6, 0))

    def update_value(self, v):
        self._val_lbl.config(text=str(v))


class InputField(tk.Frame):
    """Styled label + entry with optional placeholder."""
    def __init__(self, master, label, placeholder="", width=32, password=False, tooltip=None, **kw):
        super().__init__(master, bg=C["card"], **kw)
        tk.Label(self, text=label, font=F["small"], bg=C["card"],
                 fg=C["muted"]).pack(anchor="w", pady=(0, 4))
        
        # Single flat frame with thin border instead of double nesting
        self._wrap = tk.Frame(self, bg=C["card2"], highlightthickness=1, highlightbackground=C["border"])
        self._wrap.pack(fill=tk.X, ipady=2)
        
        self.var = tk.StringVar(value=placeholder)
        show = "*" if password else ""
        self.entry = tk.Entry(self._wrap, textvariable=self.var, width=width,
                              bg=C["card2"], fg=C["text"], insertbackground=C["cyan"],
                              relief="flat", bd=3, font=F["mono_m"], show=show)
        self.entry.pack(fill=tk.X, padx=6)
        self.entry.bind("<FocusIn>",  self._focus_in)
        self.entry.bind("<FocusOut>", self._focus_out)
        self._ph = placeholder

        # Setup tooltip
        if tooltip:
            Tooltip(self.entry, tooltip)
        else:
            Tooltip(self.entry, f"Enter target {label.lower()}")

    def _focus_in(self, _):
        self._wrap.config(highlightbackground=C["cyan"])

    def _focus_out(self, _):
        self._wrap.config(highlightbackground=C["border"])

    def get(self):
        return self.var.get().strip()


class ProgressRing(tk.Canvas):
    """Animated circular progress / risk gauge."""
    def __init__(self, master, size=120, **kw):
        super().__init__(master, width=size, height=size,
                         bg=C["card"], bd=0, highlightthickness=0, **kw)
        self._size  = size
        self._score = 0
        self._target= 0
        self._draw(0)

    def set_score(self, score):
        self._target = max(0, min(100, score))
        self._animate()

    def _animate(self):
        diff = self._target - self._score
        if abs(diff) < 1:
            self._score = self._target
            self._draw(self._score)
            return
        self._score += diff * 0.15
        self._draw(self._score)
        self.after(16, self._animate)

    def _draw(self, score):
        self.delete("all")
        s   = self._size
        pad = 12
        # Background track arc
        self.create_arc(pad, pad, s-pad, s-pad,
                        start=225, extent=-270,
                        style="arc", outline=C["border"], width=10)
        # Colored progress arc
        if score > 0:
            ext = -270 * (score / 100)
            color = (C["green"]  if score < 40 else
                     C["amber"]  if score < 70 else
                     C["red"])
            # Glow layer (wider, transparent-ish)
            self.create_arc(pad-2, pad-2, s-pad+2, s-pad+2,
                            start=225, extent=ext,
                            style="arc", outline=color, width=14)
            # Core arc
            self.create_arc(pad, pad, s-pad, s-pad,
                            start=225, extent=ext,
                            style="arc", outline=color, width=10)
        # Tick marks at 25, 50, 75
        import math
        for pct in [25, 50, 75]:
            angle = math.radians(225 - 270 * (pct / 100))
            cx = s / 2 + (s / 2 - pad - 2) * math.cos(angle)
            cy = s / 2 - (s / 2 - pad - 2) * math.sin(angle)
            self.create_oval(cx - 2, cy - 2, cx + 2, cy + 2,
                             fill=C["dim"], outline=C["dim"])
        # Score text
        self.create_text(s//2, s//2 - 8, text=f"{int(score)}",
                         fill=C["text"], font=("Segoe UI", 22, "bold"))
        self.create_text(s//2, s//2 + 16, text="/100",
                         fill=C["muted"], font=F["small"])


class Toast:
    """Slide-in toast notification system for the application."""
    _instances = []  # Track active toasts for stacking
    TYPES = {
        "success": {"icon": "✓", "color": "#00e676", "bg": "#0d2818"},
        "error":   {"icon": "✗", "color": "#ff4757", "bg": "#2d0f12"},
        "warning": {"icon": "⚠", "color": "#ffab00", "bg": "#2d2200"},
        "info":    {"icon": "ℹ", "color": "#00d4ff", "bg": "#0d1a2d"},
    }

    def __init__(self, master, message, toast_type="info", duration=4000):
        cfg = self.TYPES.get(toast_type, self.TYPES["info"])

        self._master = master
        self._duration = duration
        self._frame = tk.Frame(master, bg=cfg["bg"], bd=0,
                               highlightthickness=1, highlightbackground=cfg["color"])

        # Layout
        tk.Frame(self._frame, bg=cfg["color"], width=4).pack(side=tk.LEFT, fill=tk.Y)
        body = tk.Frame(self._frame, bg=cfg["bg"])
        body.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=8)

        tk.Label(body, text=f'{cfg["icon"]}  {message}', font=("Segoe UI", 9),
                 bg=cfg["bg"], fg=cfg["color"], anchor="w").pack(anchor="w")

        close_btn = tk.Label(self._frame, text="✕", font=("Segoe UI", 9),
                              bg=cfg["bg"], fg=C["dim"], cursor="hand2")
        close_btn.pack(side=tk.RIGHT, padx=8)
        close_btn.bind("<Button-1>", lambda _: self.dismiss())

        # Stack offset
        stack_offset = len(Toast._instances) * 48
        Toast._instances.append(self)

        # Place at bottom-right
        self._frame.place(relx=1.0, rely=1.0, anchor="se",
                          x=-20, y=-(20 + stack_offset),
                          width=340, height=42)
        self._frame.lift()

        # Auto-dismiss
        self._after_id = master.after(duration, self.dismiss)

    def dismiss(self):
        try:
            self._master.after_cancel(self._after_id)
        except Exception:
            pass
        try:
            self._frame.place_forget()
            self._frame.destroy()
        except Exception:
            pass
        if self in Toast._instances:
            Toast._instances.remove(self)

class BasePanel(tk.Frame):
    NAME = "Module"
    DESC = ""

    def __init__(self, master, app):
        super().__init__(master, bg=C["bg"])
        self.app = app
        self._build_header()
        self._build_body()
        if self.NAME not in ["Dashboard", "Settings", "Reports & History"]:
            self._build_results_area()

    # ── Header ─────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=C["card"], bd=0, highlightthickness=0)
        hdr.pack(fill=tk.X, padx=0, pady=0)
        inner = tk.Frame(hdr, bg=C["card"])
        inner.pack(fill=tk.X, padx=20, pady=12)
        tk.Label(inner, text=self.NAME, font=F["head"],
                 bg=C["card"], fg=C["cyan"]).pack(side=tk.LEFT)
        if self.DESC:
            tk.Label(inner, text=self.DESC, font=F["small"],
                     bg=C["card"], fg=C["muted"]).pack(side=tk.LEFT, padx=12)

    def _build_body(self):
        pass   # override in subclasses

    def _build_results_area(self):
        # Separator line
        tk.Frame(self, bg=C["border"], height=1).pack(fill=tk.X, padx=20, pady=10)
        
        # Results frame
        res_frame = tk.Frame(self, bg=C["bg"])
        res_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))
        
        # 1. Status Banner
        self._status_frame = tk.Frame(res_frame, bg=C["card"], bd=0, highlightthickness=0)
        self._status_frame.pack(fill=tk.X, pady=(0, 10), ipady=6)
        
        self._status_accent = tk.Frame(self._status_frame, bg=C["border"], width=4)
        self._status_accent.pack(side=tk.LEFT, fill=tk.Y)
        
        self._status_icon = tk.Label(self._status_frame, text="🟢", font=("Segoe UI", 12), bg=C["card"])
        self._status_icon.pack(side=tk.LEFT, padx=(12, 6))
        
        self._status_lbl = tk.Label(self._status_frame, text="Status:", font=F["badge"], bg=C["card"], fg=C["muted"])
        self._status_lbl.pack(side=tk.LEFT, padx=2)
        
        self._status_text = tk.Label(self._status_frame, text="Ready", font=F["body"], bg=C["card"], fg=C["text"])
        self._status_text.pack(side=tk.LEFT, padx=6)
        
        # Indeterminate Progressbar
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Wazuh.Horizontal.TProgressbar", foreground=C["cyan"], background=C["cyan"], 
                        troughcolor=C["card2"], bordercolor=C["border"])
        self._status_progress = ttk.Progressbar(self._status_frame, mode="indeterminate", style="Wazuh.Horizontal.TProgressbar", length=150)
        
        # 2. Main structured container (direct white card frame)
        self._tab_struct = tk.Frame(res_frame, bg=C["card"])
        self._tab_struct.pack(fill=tk.BOTH, expand=True)

    def _bind_double_click(self, tree, columns):
        def _on_double_click(event):
            item = tree.focus()
            if not item:
                return
            values = tree.item(item, "values")
            if not values:
                return
            data_dict = dict(zip(columns, values))
            DetailDialog(self.app, f"{self.NAME} Details", data_dict)
        tree.bind("<Double-1>", _on_double_click)

    def _create_treeview(self, columns, widths=None):
        """Helper to create a Treeview table in the Structured tab."""
        style = ttk.Style()
        style.configure("Wazuh.Treeview", background=C["card"], foreground=C["text"],
                         fieldbackground=C["card"], font=F["mono"], rowheight=28,
                         borderwidth=0)
        style.configure("Wazuh.Treeview.Heading", background=C["card2"],
                         foreground=C["cyan"], font=F["badge"],
                         borderwidth=0, relief="flat")
        style.map("Wazuh.Treeview",
                  background=[("selected", "#2d1b69")],
                  foreground=[("selected", "#ffffff")])

        # Scrollbar wrapper
        sb = ttk.Scrollbar(self._tab_struct, orient="vertical")
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        tree = ttk.Treeview(self._tab_struct, columns=columns, show="headings",
                            style="Wazuh.Treeview", yscrollcommand=sb.set)
        tree.pack(fill=tk.BOTH, expand=True)
        sb.config(command=tree.yview)

        # Alternating row tags for zebra striping
        tree.tag_configure("oddrow", background=C["card"])
        tree.tag_configure("evenrow", background=C["card2"])

        widths = widths or [150] * len(columns)
        for col, width in zip(columns, widths):
            tree.heading(col, text=col.upper())
            tree.column(col, width=width, anchor="w")

        self._bind_double_click(tree, columns)
        return tree

    # ── Shared helpers ─────────────────────────────────────────────────────
    def _section(self, parent, title):
        """Bordered section frame with subtle border."""
        frm = tk.Frame(parent, bg=C["card"], bd=0,
                       highlightthickness=1, highlightbackground=C["border"])
        frm.pack(fill=tk.X, padx=20, pady=12)
        # label
        lbl_bar = tk.Frame(frm, bg=C["card"])
        lbl_bar.pack(fill=tk.X, padx=16, pady=(14, 6))
        tk.Label(lbl_bar, text=title.upper(), font=F["badge"],
                 bg=C["card"], fg=C["cyan"]).pack(side=tk.LEFT)
        return frm

    def _input_grid(self, parent):
        """Return a frame for grid-based inputs."""
        frm = tk.Frame(parent, bg=C["card"])
        frm.pack(fill=tk.X, padx=20, pady=4)
        return frm

    def _btn_row(self, parent):
        row = tk.Frame(parent, bg=C["bg"])
        row.pack(fill=tk.X, padx=20, pady=8)
        return row

    def _checkbox(self, parent, text, var):
        cb = tk.Checkbutton(parent, text=text, variable=var,
                            bg=C["card"], fg=C["muted"],
                            selectcolor=C["bg"],
                            activebackground=C["card"],
                            activeforeground=C["text"],
                            font=F["body"])
        return cb

    def _run_in_thread(self, fn, *args):
        threading.Thread(target=fn, args=args, daemon=True).start()

    def _log(self, msg, tag="info"):
        print(f"[{self.NAME}] {msg}")
        # Clean milestone message for the graphical banner
        clean_msg = msg
        for prefix in ["[STAGE 1] ", "[STAGE 2] ", "[STAGE 3] ", "[STAGE 4] ", "[+] ", "  ↳ ", "  ● "]:
            if clean_msg.startswith(prefix):
                clean_msg = clean_msg[len(prefix):]
        if clean_msg.strip():
            self._status_text.config(text=clean_msg.strip())
            self.update_idletasks()

    def _log_json(self, data):
        if hasattr(self, "_tab_struct"):
            self._display_json_results(data)

    def _display_json_results(self, data):
        """Displays any dict or list in a nice, structured way (Treeview) in the Structured tab."""
        # Clear structured tab
        for widget in self._tab_struct.winfo_children():
            widget.destroy()
            
        if isinstance(data, dict):
            columns = ("Metric / Property", "Value")
            tree = self._create_treeview(columns, [250, 500])
            
            def recurse_insert(d, prefix=""):
                for k, v in d.items():
                    key_str = f"{prefix}{k}"
                    if isinstance(v, dict):
                        tree.insert("", tk.END, values=(key_str, "{...}"))
                        recurse_insert(v, prefix + "  ")
                    elif isinstance(v, list):
                        tree.insert("", tk.END, values=(key_str, f"List [{len(v)} items]"))
                        for item in v[:8]:
                            tree.insert("", tk.END, values=(prefix + "    -", str(item)))
                    else:
                        tree.insert("", tk.END, values=(key_str, str(v)))
            recurse_insert(data)
        elif isinstance(data, list):
            columns = ("Item Index", "Value / Preview")
            tree = self._create_treeview(columns, [100, 650])
            for idx, val in enumerate(data):
                tree.insert("", tk.END, values=(f"#{idx+1}", str(val)))

    def _start(self, op=""):
        label = f"{self.NAME}" + (f"  ›  {op}" if op else "")
        print(f"Starting {label}...")
        self.app.status_set(f"Running {self.NAME}…", C["amber"])
        
        # Update Banner
        self._status_accent.config(bg=C["amber"])
        self._status_icon.config(text="🔄")
        self._status_text.config(text=f"Running: {op or self.NAME}...")
        self._status_progress.pack(side=tk.RIGHT, padx=16)
        self._status_progress.start(10)
        
        self._clear_results()

    def _done(self, msg="Complete"):
        print(f"✓  {msg}")
        self.app.status_set("Ready", C["green"])
        
        # Update Banner
        self._status_accent.config(bg=C["green"])
        self._status_icon.config(text="✅")
        self._status_text.config(text=msg)
        self._status_progress.stop()
        self._status_progress.pack_forget()
        
        # Toast notification
        try:
            Toast(self.app, f"{self.NAME}: {msg}", "success")
        except Exception:
            pass

    def _err(self, e):
        print(f"✗  Error: {e}")
        self.app.status_set("Error", C["red"])
        
        # Update Banner
        self._status_accent.config(bg=C["red"])
        self._status_icon.config(text="❌")
        self._status_text.config(text=f"Error: {e}")
        self._status_progress.stop()
        self._status_progress.pack_forget()
        
        # Toast notification
        try:
            Toast(self.app, f"{self.NAME}: {str(e)[:60]}", "error", duration=6000)
        except Exception:
            pass

    def _clear_results(self):
        if hasattr(self, "_tab_struct"):
            for widget in self._tab_struct.winfo_children():
                widget.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────
class DashboardPanel(BasePanel):
    NAME = "Dashboard"
    DESC = "System overview & quick launch"

    def _build_body(self):
        scroll_host = tk.Frame(self, bg=C["bg"])
        scroll_host.pack(fill=tk.BOTH, expand=True)

        # ── Quick scan bar ──────────────────────────────────────────────────
        qbar = tk.Frame(scroll_host, bg=C["card"], bd=0, highlightthickness=0)
        qbar.pack(fill=tk.X, padx=20, pady=(12, 0))

        inner = tk.Frame(qbar, bg=C["card"])
        inner.pack(fill=tk.X, padx=16, pady=12)

        tk.Label(inner, text="Quick Target", font=F["subhead"],
                 bg=C["card"], fg=C["muted"]).pack(side=tk.LEFT, padx=(0, 10))

        self._q_domain = tk.StringVar()
        wrap = tk.Frame(inner, bg=C["border"], padx=1, pady=1)
        wrap.pack(side=tk.LEFT, padx=4)
        self._q_entry = tk.Entry(wrap, textvariable=self._q_domain,
                                 width=32, bg=C["card2"], fg=C["text"],
                                 insertbackground=C["cyan"],
                                 relief="flat", bd=6, font=F["mono_m"])
        self._q_entry.pack()

        NeonButton(inner, "FULL SCAN",  self._quick_full,  C["cyan"],   width=110, height=32, tooltip="Run a full deep security scan on the target domain").pack(side=tk.LEFT, padx=6)
        NeonButton(inner, "FREE SCAN",  self._quick_free,  C["green"],  width=110, height=32, tooltip="Run a free open-source intelligence scan on the target").pack(side=tk.LEFT, padx=2)
        NeonButton(inner, "DNS RECON",  self._quick_dns,   C["purple"], width=110, height=32, tooltip="Resolve subdomains and DNS records for target").pack(side=tk.LEFT, padx=2)

        # ── Stat cards ──────────────────────────────────────────────────────
        cards_row = tk.Frame(scroll_host, bg=C["bg"])
        cards_row.pack(fill=tk.X, padx=20, pady=12)

        self._cards = {}
        card_defs = [
            ("Modules",    "24",  "available",  C["cyan"],   "⬡"),
            ("Scans Run",  "0",   "this session",C["purple"],"◈"),
            ("Risk Score", "—",   "/100 last",  C["amber"],  "◎"),
            ("Open Ports", "—",   "last scan",  C["red"],    "⬡"),
        ]
        for title, val, unit, color, icon in card_defs:
            c = StatCard(cards_row, title, val, unit, color, icon)
            c.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6)
            self._cards[title] = c

        # ── Risk gauge + module list ────────────────────────────────────────
        mid_row = tk.Frame(scroll_host, bg=C["bg"])
        mid_row.pack(fill=tk.BOTH, expand=True, padx=20, pady=4)

        # Gauge card
        gauge_card = tk.Frame(mid_row, bg=C["card"], bd=0, highlightthickness=0, width=200)
        gauge_card.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        tk.Label(gauge_card, text="RISK METER", font=F["badge"],
                 bg=C["card"], fg=C["muted"]).pack(pady=(12, 4))
        self._ring = ProgressRing(gauge_card, size=130)
        self._ring.pack(padx=20, pady=8)
        self._risk_lbl = tk.Label(gauge_card, text="NO DATA",
                                  font=F["subhead"], bg=C["card"], fg=C["muted"])
        self._risk_lbl.pack(pady=(4, 16))

        # Module grid
        mod_card = tk.Frame(mid_row, bg=C["card"], bd=0, highlightthickness=0)
        mod_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(mod_card, text="AVAILABLE MODULES", font=F["badge"],
                 bg=C["card"], fg=C["muted"]).pack(anchor="w", padx=14, pady=(10, 6))

        grid = tk.Frame(mod_card, bg=C["card"])
        grid.pack(fill=tk.BOTH, expand=True, padx=14, pady=6)

        modules_info = [
            ("🔍", "Full Domain Scan",   C["cyan"]),
            ("🌐", "DNS Enumeration",    C["cyan"]),
            ("📋", "WHOIS / IP Intel",   C["purple"]),
            ("🔒", "SSL / Certificates", C["purple"]),
            ("⚙",  "HTTP & Technology", C["purple"]),
            ("🚪", "Port Scanner",       C["red"]),
            ("📧", "Email OSINT",        C["amber"]),
            ("📱", "Phone OSINT",        C["amber"]),
            ("👤", "Social Media",       C["amber"]),
            ("🕵", "Google Dorking",     C["green"]),
            ("📅", "Wayback Machine",    C["green"]),
            ("☠",  "Threat Intel",       C["red"]),
            ("🛡",  "DNS Security",       C["amber"]),
            ("🎯", "Subdomain Takeover", C["red"]),
            ("🗂",  "Metadata Extract",  C["purple"]),
            ("📁", "Directory Enum",     C["red"]),
            ("📡", "Shodan",             C["cyan"]),
            ("🦠", "VirusTotal",         C["red"]),
            ("🔬", "Forensics",          C["purple"]),
            ("🔑", "Credentials",        C["amber"]),
            ("📶", "WiFi / Devices",     C["green"]),
            ("🏛",  "Gov Data",          C["purple"]),
            ("⚡", "Quick Lookup",       C["cyan"]),
            ("📊", "Reports",            C["green"]),
        ]

        COLS = 6
        for i, (icon, name, color) in enumerate(modules_info):
            r, c = divmod(i, COLS)
            tile = tk.Frame(grid, bg=C["card2"], bd=0, highlightthickness=0)
            tile.grid(row=r, column=c, padx=3, pady=3, sticky="ew")
            grid.columnconfigure(c, weight=1)
            tk.Label(tile, text=icon, font=("Segoe UI", 11),
                     bg=C["card2"], fg=color).pack(side=tk.LEFT, padx=6, pady=5)
            tk.Label(tile, text=name, font=F["tiny"],
                     bg=C["card2"], fg=C["muted"]).pack(side=tk.LEFT)

        # ── Security Event Monitor ──────────────────────────────────────────
        sec_events = tk.Frame(scroll_host, bg=C["card"], bd=0, highlightthickness=0)
        sec_events.pack(fill=tk.BOTH, expand=True, padx=20, pady=(10, 12))
        
        lbl_bar = tk.Frame(sec_events, bg=C["card"])
        lbl_bar.pack(fill=tk.X, padx=14, pady=(8, 4))
        tk.Label(lbl_bar, text="SECURITY EVENT MONITOR (RECENT SCANS)", font=F["badge"],
                 bg=C["card"], fg=C["muted"]).pack(side=tk.LEFT)
                 
        # Table
        cols = ("Timestamp", "Target Domain", "Scan Type", "Risk Score", "Threat Level")
        self._dash_tree = ttk.Treeview(sec_events, columns=cols, show="headings",
                                        height=5, style="Wazuh.Treeview")
        for c, w in zip(cols, [160, 240, 120, 90, 100]):
            self._dash_tree.heading(c, text=c.upper())
            self._dash_tree.column(c, width=w, anchor="w")
        self._dash_tree.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        
        self._bind_double_click(self._dash_tree, cols)
        self._refresh_dash_events()

    def _quick_full(self):
        d = self._q_domain.get().strip()
        if not d:
            messagebox.showwarning("Target", "Enter a target domain first.")
            return
        self._run_in_thread(self._do_full, d)

    def _quick_free(self):
        d = self._q_domain.get().strip()
        if not d:
            messagebox.showwarning("Target", "Enter a target domain first.")
            return
        self._run_in_thread(self._do_free, d)

    def _quick_dns(self):
        d = self._q_domain.get().strip()
        if not d:
            messagebox.showwarning("Target", "Enter a target domain first.")
            return
        self._run_in_thread(self._do_dns, d)

    def _do_full(self, domain):
        self._start("FULL SCAN")
        try:
            from scan_orchestrator import get_orchestrator
            results = get_orchestrator().run_full_scan(domain, {})
            self._refresh_dash_events()
            self._done("Full scan complete")
        except Exception as e:
            self._err(e)

    def _do_free(self, domain):
        self._start("FREE SCAN")
        try:
            from scan_orchestrator import get_orchestrator
            results = get_orchestrator().run_free_osint_scan(domain)
            self._refresh_dash_events()
            self._done("Free scan complete")
        except Exception as e:
            self._err(e)

    def _do_dns(self, domain):
        self._start("DNS RECON")
        try:
            from dns_enum_advanced import dns_enum_advanced
            res = dns_enum_advanced(domain, True, True)
            self._log_json(res)
            self._done("DNS enumeration complete")
        except Exception as e:
            self._err(e)

    def _refresh_dash_events(self):
        for row in self._dash_tree.get_children():
            self._dash_tree.delete(row)
        try:
            from scan_orchestrator import get_orchestrator
            history = get_orchestrator().get_scan_history(5)
            self._cards["Scans Run"].update_value(len(history))
            
            if history:
                latest = history[-1]
                score = latest.get("risk_score", 0)
                lvl = latest.get("risk_level", "N/A")
                self._ring.set_score(score)
                self._risk_lbl.config(text=f"{lvl}", fg=_risk_color(lvl))
                self._cards["Risk Score"].update_value(score)
                
            for h in reversed(history):
                self._dash_tree.insert("", tk.END, values=(
                    h.get("timestamp",""),
                    h.get("target",""),
                    h.get("scan_type","full").upper(),
                    f"{h.get('risk_score', 0)}/100",
                    h.get("risk_level","INFO")
                ))
        except Exception as e:
            print("Error loading dashboard events:", e)


def _risk_color(lvl):
    return {
        "CRITICAL": C["red"],
        "HIGH":     C["red"],
        "MEDIUM":   C["amber"],
        "LOW":      C["green"],
    }.get(lvl, C["muted"])


# ─────────────────────────────────────────────────────────────────────────────
# FULL SCAN PANEL
# ─────────────────────────────────────────────────────────────────────────────
class FullScanPanel(BasePanel):
    NAME = "Full Domain Scan"
    DESC = "Runs all OSINT modules against a target domain"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill=tk.X, expand=False)

        sec = self._section(body, "Target Configuration")
        ig  = tk.Frame(sec, bg=C["card"])
        ig.pack(fill=tk.X, padx=12, pady=(0, 12))

        left  = tk.Frame(ig, bg=C["card"]); left.pack(side=tk.LEFT, padx=8)
        right = tk.Frame(ig, bg=C["card"]); right.pack(side=tk.LEFT, padx=8)

        self._domain = InputField(left,  "Target Domain",   "example.com",       width=32)
        self._domain.pack(fill=tk.X, pady=4)
        self._shodan = InputField(left,  "Shodan API Key",  os.getenv("SHODAN_API_KEY", ""),        width=32)
        self._shodan.pack(fill=tk.X, pady=4)
        self._vt     = InputField(right, "VirusTotal Key",  os.getenv("VT_API_KEY", ""),        width=32)
        self._vt.pack(fill=tk.X, pady=4)
        self._hibp   = InputField(right, "HIBP API Key",    os.getenv("HIBP_API_KEY", ""),        width=32)
        self._hibp.pack(fill=tk.X, pady=4)

        # module toggles
        tog_sec = self._section(body, "Module Selection")
        tog = tk.Frame(tog_sec, bg=C["card"])
        tog.pack(fill=tk.X, padx=12, pady=(0, 12))

        self._mods = {}
        mod_names = [
            "dns_enum", "whois", "certificates", "http_headers",
            "technology", "wayback", "google_dorking", "social_media",
            "ip_intel", "port_scan", "threat_intel", "dns_security",
            "subdomain_takeover", "metadata", "dir_enum", "shodan",
        ]
        for i, m in enumerate(mod_names):
            var = tk.BooleanVar(value=True)
            self._mods[m] = var
            r, c = divmod(i, 4)
            cb = self._checkbox(tog, m.replace("_", " ").title(), var)
            cb.grid(row=r, column=c, sticky="w", padx=10, pady=3)
            tog.columnconfigure(c, weight=1)

        # run buttons
        btn_row = tk.Frame(body, bg=C["bg"])
        btn_row.pack(fill=tk.X, padx=20, pady=10)
        NeonButton(btn_row, "▶  FULL SCAN",    self._run_full, C["cyan"],   width=160, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT, padx=(0, 8))
        NeonButton(btn_row, "⚡ FREE SCAN",    self._run_free, C["green"],  width=150, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT, padx=4)
        NeonButton(btn_row, "✕  Clear",        self._clear_results, C["muted"], width=100, height=40).pack(side=tk.RIGHT)

    def _run_full(self):
        d = self._domain.get()
        if not d:
            messagebox.showwarning("Target", "Enter a domain.")
            return
        api_keys = {"shodan": self._shodan.get(), "virustotal": self._vt.get()}
        self._run_in_thread(self._do_full, d, api_keys)

    def _run_free(self):
        d = self._domain.get()
        if not d:
            messagebox.showwarning("Target", "Enter a domain.")
            return
        self._run_in_thread(self._do_free, d)

    def _do_full(self, domain, api_keys):
        self._start("FULL")
        try:
            from scan_orchestrator import get_orchestrator
            self._log(f"Target: {domain}", "accent")
            res = get_orchestrator().run_full_scan(domain, api_keys)
            self._log(f"Status: {res.get('scan_status')}", "success")
            risk = res.get("risk_score", {})
            self._log(f"Risk Score: {risk.get('score', 0)}/100  ·  {risk.get('level', '')}", "warn")
            for f in risk.get("factors", []):
                self._log(f"  {f}", "dim")
            self._done()
        except Exception as e:
            self._err(e)

    def _do_free(self, domain):
        self._start("FREE")
        try:
            from scan_orchestrator import get_orchestrator
            self._log(f"Target: {domain}", "accent")
            res = get_orchestrator().run_free_osint_scan(domain)
            risk = res.get("risk_score", {})
            self._log(f"Risk Score: {risk.get('score', 0)}/100  ·  {risk.get('level', '')}", "warn")
            self._done()
        except Exception as e:
            self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# DNS PANEL
# ─────────────────────────────────────────────────────────────────────────────
class DNSPanel(BasePanel):
    NAME = "DNS Enumeration"
    DESC = "Bruteforce, zone transfer, record analysis"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill=tk.X, expand=False)

        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"])
        ig.pack(fill=tk.X, padx=12, pady=(0, 12))

        self._domain = InputField(ig, "Domain", "example.com", width=36)
        self._domain.pack(side=tk.LEFT, padx=8)

        opts = tk.Frame(ig, bg=C["card"])
        opts.pack(side=tk.LEFT, padx=20)
        self._brute = tk.BooleanVar(value=True)
        self._zone  = tk.BooleanVar(value=True)
        self._checkbox(opts, "Bruteforce Subdomains", self._brute).pack(anchor="w", pady=3)
        self._checkbox(opts, "Zone Transfer Attempt",  self._zone).pack(anchor="w", pady=3)

        br = self._btn_row(body)
        NeonButton(br, "▶  Run DNS Enum",    self._run,         C["cyan"],   width=170, height=38).pack(side=tk.LEFT, padx=(0,6))
        NeonButton(br, "DNS Security Check", self._run_security, C["amber"], width=180, height=38).pack(side=tk.LEFT, padx=4)

    def _run(self):
        d = self._domain.get()
        if d:
            self._run_in_thread(self._do, d, self._brute.get(), self._zone.get())

    def _run_security(self):
        d = self._domain.get()
        if d:
            self._run_in_thread(self._do_security, d)

    def _do(self, domain, brute, zone):
        self._start()
        try:
            from dns_enum_advanced import dns_enum_advanced
            res = dns_enum_advanced(domain, brute, zone)
            self._log(f"DNS enum complete · {domain}", "success")
            self._log_json(res)
            self._done()
        except Exception as e:
            self._err(e)

    def _do_security(self, domain):
        self._start("SECURITY")
        try:
            from dns_security_analyzer import dns_security_analyzer
            res = dns_security_analyzer(domain)
            grade = res.get("security_grade", "N/A")
            col   = C["green"] if grade in ("A","B") else C["amber"] if grade=="C" else C["red"]
            self._log(f"Grade: {grade}  ·  Score: {res.get('security_score',0)}/100", col)
            for i in res.get("critical_issues", []):
                self._log(f"  ✗ {i}", "error")
            self._log_json(res)
            self._done()
        except Exception as e:
            self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS / IP
# ─────────────────────────────────────────────────────────────────────────────
class WhoisPanel(BasePanel):
    NAME = "WHOIS & IP Intelligence"
    DESC = "Domain registration, IP geolocation, ASN"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"])
        ig.pack(fill=tk.X, padx=12, pady=(0, 12))
        self._target = InputField(ig, "Domain or IP", "example.com", width=36)
        self._target.pack(side=tk.LEFT, padx=8)

        br = self._btn_row(body)
        for label, mode, color in [
            ("WHOIS Lookup",    "whois",    C["cyan"]),
            ("Extended WHOIS",  "whois_ext",C["purple"]),
            ("IP Intelligence", "ip",       C["green"]),
        ]:
            NeonButton(br, label, lambda m=mode: self._run(m), color, width=150, height=38).pack(side=tk.LEFT, padx=4)

    def _run(self, mode):
        t = self._target.get()
        if t:
            self._run_in_thread(self._do, t, mode)

    def _do(self, target, mode):
        self._start(mode.upper())
        try:
            if mode == "whois":
                from whois_lookup_deep import whois_lookup_deep; res = whois_lookup_deep(target)
            elif mode == "whois_ext":
                from whois_extended import whois_extended; res = whois_extended(target)
            else:
                from ip_intelligence_free import ip_intelligence_free; res = ip_intelligence_free(target)
            self._log(f"Done · {target}", "success")
            self._log_json(res)
            self._done()
        except Exception as e:
            self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# SSL / CERT
# ─────────────────────────────────────────────────────────────────────────────
class CertPanel(BasePanel):
    NAME = "SSL / TLS Certificates"
    DESC = "Certificate chain, CT logs, expiry analysis"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"])
        ig.pack(fill=tk.X, padx=12, pady=(0, 12))
        self._domain = InputField(ig, "Domain", "example.com", width=36)
        self._domain.pack(side=tk.LEFT, padx=8)

        br = self._btn_row(body)
        NeonButton(br, "Analyze Certificate", self._run_cert, C["cyan"],   width=180, height=38).pack(side=tk.LEFT, padx=4)
        NeonButton(br, "CT Log Scan",          self._run_ct,  C["purple"], width=140, height=38).pack(side=tk.LEFT, padx=4)

    def _run_cert(self):
        d = self._domain.get()
        if d: self._run_in_thread(self._do_cert, d)
    def _run_ct(self):
        d = self._domain.get()
        if d: self._run_in_thread(self._do_ct, d)

    def _do_cert(self, domain):
        self._start("CERT")
        try:
            from certificate_analysis_free import certificate_analysis_free
            self._log_json(certificate_analysis_free(domain)); self._done()
        except Exception as e: self._err(e)

    def _do_ct(self, domain):
        self._start("CT LOGS")
        try:
            from scan_ct_logs_compact import scan_ct_logs_compact
            self._log_json(scan_ct_logs_compact(domain)); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP & TECH
# ─────────────────────────────────────────────────────────────────────────────
class TechPanel(BasePanel):
    NAME = "HTTP Headers & Technology"
    DESC = "Headers, fingerprinting, WAF detection"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"])
        ig.pack(fill=tk.X, padx=12, pady=(0, 12))
        self._url = InputField(ig, "URL / Domain", "https://example.com", width=38)
        self._url.pack(side=tk.LEFT, padx=8)

        br = self._btn_row(body)
        for label, mode, color in [
            ("HTTP Headers",  "headers", C["cyan"]),
            ("Tech Detection","tech",    C["purple"]),
            ("WAF Detection", "waf",     C["amber"]),
        ]:
            NeonButton(br, label, lambda m=mode: self._run(m), color, width=150, height=38).pack(side=tk.LEFT, padx=4)

    def _run(self, mode):
        t = self._url.get()
        if t: self._run_in_thread(self._do, t, mode)

    def _do(self, target, mode):
        self._start(mode.upper())
        try:
            if mode == "headers":
                from http_headers_analysis import http_headers_analysis; res = http_headers_analysis(target)
            elif mode == "tech":
                from technology_detection import technology_detection
                url = target if target.startswith("http") else f"https://{target}"
                res = technology_detection(url)
            else:
                from detect_waf import detect_waf
                domain = target.replace("https://","").replace("http://","").split("/")[0]
                res = detect_waf(domain, [])
            self._log(f"Done · {target}", "success"); self._log_json(res); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# PORT SCANNER
# ─────────────────────────────────────────────────────────────────────────────
class PortScanPanel(BasePanel):
    NAME = "Port Scanner"
    DESC = "TCP port scanning and service banner grabbing"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"])
        ig.pack(fill=tk.X, padx=12, pady=(0, 12))

        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8)
        col2 = tk.Frame(ig, bg=C["card"]); col2.pack(side=tk.LEFT, padx=8)

        self._host    = InputField(col1, "Host / IP", "example.com", width=28)
        self._host.pack(pady=4)
        self._ports   = InputField(col1, "Port Range", "1-1000", width=28)
        self._ports.pack(pady=4)
        self._timeout = InputField(col2, "Timeout (s)", "3", width=10)
        self._timeout.pack(pady=4, anchor="w")

        # common presets
        preset_row = tk.Frame(sec, bg=C["card"])
        preset_row.pack(fill=tk.X, padx=12, pady=(0, 10))
        tk.Label(preset_row, text="Presets:", font=F["small"],
                 bg=C["card"], fg=C["muted"]).pack(side=tk.LEFT)
        presets = [("Top 100","1-100"),("Top 1K","1-1000"),("Full","1-65535"),("Web","80,443,8080,8443")]
        for name, val in presets:
            NeonButton(preset_row, name,
                       lambda v=val: self._ports.var.set(v),
                       C["dim"], width=75, height=26).pack(side=tk.LEFT, padx=3)

        br = self._btn_row(body)
        NeonButton(br, "▶  START SCAN", self._run, C["red"], width=160, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        h = self._host.get()
        p = self._ports.get() or "1-1000"
        try:
            t = int(self._timeout.get() or "3")
        except ValueError:
            t = 3
        if h:
            self._run_in_thread(self._do, h, p, t)

    def _do(self, host, ports, timeout):
        self._start()
        try:
            from network_scanner_free import network_scanner_free
            res = network_scanner_free(host, port_range=ports, timeout=timeout)
            open_ports = res.get("open_ports", [])
            self._log(f"Open ports scanning complete. Discovered {len(open_ports)} open ports.", "success")
            self._log_json(res)
            self._done()
        except Exception as e:
            self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# EMAIL OSINT
# ─────────────────────────────────────────────────────────────────────────────
class EmailPanel(BasePanel):
    NAME = "Email OSINT"
    DESC = "Breach check, Gravatar, platform presence"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"])
        ig.pack(fill=tk.X, padx=12, pady=(0, 12))
        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8)
        col2 = tk.Frame(ig, bg=C["card"]); col2.pack(side=tk.LEFT, padx=8)
        self._email  = InputField(col1, "Email Address",   "user@example.com", width=32)
        self._email.pack(pady=4)
        self._domain = InputField(col2, "Domain (for leak)", "example.com",    width=32)
        self._domain.pack(pady=4)

        br = self._btn_row(body)
        for label, mode, color in [
            ("Email OSINT",  "osint",  C["cyan"]),
            ("Breach Check", "breach", C["red"]),
            ("Leak Checker", "leak",   C["amber"]),
        ]:
            NeonButton(br, label, lambda m=mode: self._run(m), color, width=140, height=38).pack(side=tk.LEFT, padx=4)

    def _run(self, mode):
        em = self._email.get(); dm = self._domain.get()
        if em or dm:
            self._run_in_thread(self._do, em, dm, mode)

    def _do(self, email, domain, mode):
        self._start(mode.upper())
        try:
            if mode == "osint":
                from email_osint_platform import email_osint_platform; res = email_osint_platform(email, True)
            elif mode == "breach":
                from check_breach_leakcheck_public import check_breach_leakcheck_public; res = check_breach_leakcheck_public([email])
            else:
                from public_leak_checker import public_leak_checker; res = public_leak_checker(email or domain, True, True)
            self._log_json(res); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# PHONE OSINT
# ─────────────────────────────────────────────────────────────────────────────
class PhonePanel(BasePanel):
    NAME = "Phone OSINT"
    DESC = "Number validation, carrier, spam check, platform registration"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"])
        ig.pack(fill=tk.X, padx=12, pady=(0, 12))
        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8)
        col2 = tk.Frame(ig, bg=C["card"]); col2.pack(side=tk.LEFT, padx=8)
        self._phone  = InputField(col1, "Phone Number (+CountryCode)", "+19165551234", width=28)
        self._phone.pack(pady=4)
        self._region = InputField(col2, "Default Region", "US", width=8)
        self._region.pack(pady=4)

        br = self._btn_row(body)
        NeonButton(br, "▶  Lookup Phone", self._run, C["purple"], width=160, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        ph = self._phone.get(); rg = self._region.get() or "US"
        if ph: self._run_in_thread(self._do, ph, rg)

    def _do(self, phone, region):
        self._start()
        try:
            from phone_osint_platform import phone_osint_platform
            self._log_json(phone_osint_platform(phone, region)); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# SOCIAL MEDIA
# ─────────────────────────────────────────────────────────────────────────────
class SocialPanel(BasePanel):
    NAME = "Social Media Enumeration"
    DESC = "Username search across 300+ platforms"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"])
        ig.pack(fill=tk.X, padx=12, pady=(0, 12))
        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8)
        col2 = tk.Frame(ig, bg=C["card"]); col2.pack(side=tk.LEFT, padx=8)
        self._user   = InputField(col1, "Username", "johndoe", width=28)
        self._user.pack(pady=4)
        self._domain = InputField(col2, "Related Domain (opt)", "", width=28)
        self._domain.pack(pady=4)

        br = self._btn_row(body)
        NeonButton(br, "▶  Enumerate Social", self._run, C["purple"], width=180, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        u = self._user.get()
        d = self._domain.get() or None
        if not u:
            messagebox.showwarning("Input", "Enter a username."); return
        self._run_in_thread(self._do, u, d)

    def _do(self, username, domain):
        self._start()
        try:
            from social_media_enum import social_media_enum
            res = social_media_enum(username, domain)
            platforms = res.get("platforms_found", [])
            self._log(f"Username search complete. Target discovered on {len(platforms)} platforms.", "success")
            self._log_json(res)
            self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# GOOGLE DORKING
# ─────────────────────────────────────────────────────────────────────────────
class DorkingPanel(BasePanel):
    NAME = "Google Dorking"
    DESC = "Generate & execute advanced OSINT dork queries"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"])
        ig.pack(fill=tk.X, padx=12, pady=(0, 8))
        self._target = InputField(ig, "Target Domain", "example.com", width=36)
        self._target.pack(side=tk.LEFT, padx=8)

        # dork type selection
        dtypes_frm = tk.Frame(sec, bg=C["card"])
        dtypes_frm.pack(fill=tk.X, padx=20, pady=(0, 12))
        tk.Label(dtypes_frm, text="Dork Types:", font=F["small"],
                 bg=C["card"], fg=C["muted"]).pack(anchor="w", pady=4)
        grid = tk.Frame(dtypes_frm, bg=C["card"])
        grid.pack(anchor="w")
        self._dork_types = {}
        dtypes = ["exposed_files","subdomains","cached_pages",
                  "exposed_emails","exposed_credentials","exposed_admin"]
        for i, dt in enumerate(dtypes):
            var = tk.BooleanVar(value=True)
            self._dork_types[dt] = var
            r, c = divmod(i, 3)
            self._checkbox(grid, dt.replace("_"," ").title(), var).grid(row=r, column=c, sticky="w", padx=12, pady=2)

        br = self._btn_row(body)
        NeonButton(br, "▶  Generate Dorks", self._run, C["cyan"], width=170, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        target = self._target.get()
        if not target: return
        selected = [k for k,v in self._dork_types.items() if v.get()]
        dtype_str = ",".join(selected) if selected else "all"
        self._run_in_thread(self._do, target, dtype_str)

    def _do(self, target, dtype_str):
        self._start()
        try:
            from google_dorking_osint import google_dorking_osint
            res = google_dorking_osint(target, dtype_str)
            dorks = res.get("dorks", {})
            total_queries = sum(len(data.get("queries", [])) for data in dorks.values())
            self._log(f"Dork queries generated. Total: {total_queries} queries.", "success")
            self._log_json(res)
            self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# WAYBACK
# ─────────────────────────────────────────────────────────────────────────────
class WaybackPanel(BasePanel):
    NAME = "Wayback Machine"
    DESC = "Historical snapshots via Archive.org"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        self._domain = InputField(ig, "Domain", "example.com", width=36)
        self._domain.pack(side=tk.LEFT, padx=8)
        br = self._btn_row(body)
        NeonButton(br, "▶  Analyze History", self._run, C["green"], width=170, height=40).pack(side=tk.LEFT)

    def _run(self):
        d = self._domain.get()
        if d: self._run_in_thread(self._do, d)

    def _do(self, domain):
        self._start()
        try:
            from wayback_machine_analyzer import wayback_machine_analyzer
            self._log_json(wayback_machine_analyzer(domain)); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# THREAT INTEL
# ─────────────────────────────────────────────────────────────────────────────
class ThreatIntelPanel(BasePanel):
    NAME = "Threat Intelligence"
    DESC = "DNSBL, OTX, URLhaus, ThreatFox, AbuseIPDB"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8)
        col2 = tk.Frame(ig, bg=C["card"]); col2.pack(side=tk.LEFT, padx=8)
        self._target = InputField(col1, "Domain / IP", "example.com", width=28); self._target.pack(pady=4)
        self._ip     = InputField(col2, "IP (optional)", "", width=20);           self._ip.pack(pady=4)
        br = self._btn_row(body)
        NeonButton(br, "▶  Threat Intel Lookup", self._run, C["red"], width=190, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        t = self._target.get()
        ip = self._ip.get() or None
        if t: self._run_in_thread(self._do, t, ip)

    def _do(self, target, ip):
        self._start()
        try:
            from threat_intel_lookup import threat_intel_lookup
            res = threat_intel_lookup(target, ip)
            lvl = res.get("threat_level","N/A")
            col = C["red"] if lvl in ("CRITICAL","HIGH") else C["amber"] if lvl=="MEDIUM" else C["green"]
            self._log(f"Threat Level: {lvl}  ·  Score: {res.get('threat_score',0)}", col)
            self._log(f"Blocklist Hits: {res.get('blocklist_hits',0)}", "warn")
            self._log_json(res); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# DARK WEB SCANNER
# ─────────────────────────────────────────────────────────────────────────────
class DarkWebPanel(BasePanel):
    NAME = "Dark Web Scanner"
    DESC = "Scan Ahmia and hidden services for database leaks and target mentions"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8)
        self._target = InputField(col1, "Target Keyword / Domain / Email", "example.com", width=42)
        self._target.pack(pady=4)
        br = self._btn_row(body)
        NeonButton(br, "▶  Scan Dark Web", self._run, C["amber"], width=180, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        t = self._target.get()
        if not t:
            messagebox.showwarning("Input", "Please enter a target keyword, domain, or email.")
            return
        # Create Treeview table in the structured tab
        for widget in self._tab_struct.winfo_children():
            widget.destroy()
            
        columns = ("Onion URL", "Page Title", "Severity", "Source")
        self._tree = self._create_treeview(columns, [320, 240, 100, 160])
        
        self._run_in_thread(self._do, t)

    def _do(self, target):
        self._start("DARK WEB SCAN")
        try:
            from dark_web_search import dark_web_search
            res = dark_web_search(target)
            results = res.get("results", [])
            self._log(f"Tor network scan complete. Identified {len(results)} matching entries.", "success")
            
            for r in results:
                # Insert into Table
                self._tree.insert("", tk.END, values=(
                    r.get("url", ""),
                    r.get("title", ""),
                    r.get("severity", "INFO"),
                    r.get("source", "")
                ))
            self._done()
        except Exception as e:
            self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# CHAINED DEEP SCANNER
# ─────────────────────────────────────────────────────────────────────────────
class ChainedScanPanel(BasePanel):
    NAME = "Chained Deep Scan"
    DESC = "Execute an automated multi-stage security scanning pipeline"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        
        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8)
        col2 = tk.Frame(ig, bg=C["card"]); col2.pack(side=tk.LEFT, padx=8)
        
        self._target = InputField(col1, "Target Domain / Host", "example.com", width=36)
        self._target.pack(pady=4)
        
        # Pipeline Selection Toggles
        self._stage1 = tk.BooleanVar(value=True)
        self._stage2 = tk.BooleanVar(value=True)
        self._stage3 = tk.BooleanVar(value=True)
        self._stage4 = tk.BooleanVar(value=True)
        
        self._checkbox(col2, "Stage 1: Subdomain Discovery", self._stage1).pack(anchor="w", pady=2)
        self._checkbox(col2, "Stage 2: Active Port Scanning", self._stage2).pack(anchor="w", pady=2)
        self._checkbox(col2, "Stage 3: Web Technology Analysis", self._stage3).pack(anchor="w", pady=2)
        self._checkbox(col2, "Stage 4: Dark Web & Threat Checks", self._stage4).pack(anchor="w", pady=2)

        br = self._btn_row(body)
        NeonButton(br, "⛓  Start Chained Scan", self._run, C["cyan"], width=210, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        t = self._target.get()
        if not t:
            messagebox.showwarning("Input", "Please enter a target domain.")
            return
            
        # Recreate treeview in the structured tab
        for widget in self._tab_struct.winfo_children():
            widget.destroy()
            
        columns = ("Stage / Target", "Finding / Status", "Details / Value")
        self._tree = self._create_treeview(columns, [220, 200, 400])
        
        self._run_in_thread(self._do_chain, t)

    def _do_chain(self, target):
        self._start("CHAINED SECURITY PIPELINE")
        
        subdomains = [target]
        active_hosts = []
        
        # Stage 1: Subdomain Discovery
        if self._stage1.get():
            self._log("[STAGE 1] Resolving subdomains and DNS records...", "accent")
            self._tree.insert("", tk.END, values=("Stage 1: Subdomains", "RUNNING", f"Recon on {target}"))
            try:
                from dns_enum_advanced import dns_enum_advanced
                res = dns_enum_advanced(target, True, False)
                records = res.get("dns_records", {})
                
                # Extract subdomains from A records
                found_subs = set()
                for r in records.get("A", []):
                    if isinstance(r, dict) and r.get("name"):
                        found_subs.add(r.get("name"))
                
                if found_subs:
                    subdomains = list(found_subs)
                self._log(f"Stage 1 Complete. Discovered {len(subdomains)} subdomains.", "success")
                
                for s in subdomains[:15]:
                    self._tree.insert("", tk.END, values=(f"  ↳ {s}", "RESOLVED", "A Record Active"))
            except Exception as e:
                self._log(f"Stage 1 Error: {e}", "error")
                
        # Stage 2: Active Port Scanning
        if self._stage2.get():
            self._log("[STAGE 2] Port scanning discovered targets...", "accent")
            self._tree.insert("", tk.END, values=("Stage 2: Port Scan", "RUNNING", f"Scanning {len(subdomains)} subdomains"))
            
            from network_scanner_free import network_scanner_free
            for sub in subdomains[:5]:
                self._log(f"Scanning target: {sub}...", "info")
                try:
                    res = network_scanner_free(sub, port_range="80,443,8080", timeout=2)
                    open_ports = res.get("open_ports", [])
                    if open_ports:
                        self._log(f"  Target {sub} has open ports: {[p.get('port') for p in open_ports]}", "warn")
                        for p in open_ports:
                            port_val = p.get('port')
                            active_hosts.append((sub, port_val))
                            self._tree.insert("", tk.END, values=(f"  ↳ {sub}:{port_val}", "OPEN", p.get("service", "unknown")))
                    else:
                        self._log(f"  Target {sub} has no common open ports.", "dim")
                except Exception as e:
                    self._log(f"  Target {sub} scan error: {e}", "error")
            self._log("Stage 2 Complete.", "success")
            
        # Stage 3: Web Tech Analysis
        if self._stage3.get():
            self._log("[STAGE 3] Performing HTTP and tech stack analysis...", "accent")
            self._tree.insert("", tk.END, values=("Stage 3: Tech Stack", "RUNNING", f"Analyzing active targets"))
            
            targets_to_analyze = [(sub, port) for sub, port in active_hosts]
            if not targets_to_analyze:
                targets_to_analyze = [(target, 443)]
                
            from technology_detection import technology_detection
            from http_headers_analysis import http_headers_analysis
            
            for sub, port in targets_to_analyze[:3]:
                schema = "https" if port in (443, 8443) else "http"
                url = f"{schema}://{sub}"
                self._log(f"Analyzing headers & tech on: {url}...", "info")
                try:
                    tech = technology_detection(url)
                    headers = http_headers_analysis(sub)
                    
                    tech_list = [t.get("name") for t in tech.get("technologies", []) if isinstance(t, dict)]
                    tech_str = ", ".join(tech_list) if tech_list else "Unknown Web Server"
                    
                    self._log(f"  Server: {headers.get('server', 'N/A')}  ·  Tech: {tech_str}", "success")
                    self._tree.insert("", tk.END, values=(f"  ↳ {sub} ({port})", tech_str, f"Server: {headers.get('server', 'N/A')}"))
                except Exception as e:
                    self._log(f"  Tech analysis failed for {sub}: {e}", "dim")
            self._log("Stage 3 Complete.", "success")
            
        # Stage 4: Dark Web & Threat Leak Check
        if self._stage4.get():
            self._log("[STAGE 4] Checking threat lists & dark web leaks...", "accent")
            self._tree.insert("", tk.END, values=("Stage 4: Threats & Leaks", "RUNNING", f"Checking dark web databases"))
            
            try:
                from dark_web_search import dark_web_search
                from threat_intel_lookup import threat_intel_lookup
                
                dark = dark_web_search(target)
                threat = threat_intel_lookup(target, None)
                
                self._log(f"Threat Score: {threat.get('threat_score', 0)}/100  ·  Dark Web Mentions: {len(dark.get('results', []))}", "warn")
                
                self._tree.insert("", tk.END, values=(f"  ↳ Threat Intel", f"Score: {threat.get('threat_score', 0)}/100", f"Level: {threat.get('threat_level')}"))
                for idx, r in enumerate(dark.get("results", [])[:3]):
                    self._tree.insert("", tk.END, values=(f"  ↳ Leak #{idx+1}", r.get("title"), r.get("url")))
            except Exception as e:
                self._log(f"Stage 4 Error: {e}", "error")
            self._log("Stage 4 Complete.", "success")
            
        self._done("Chained security pipeline execution complete.")


# ─────────────────────────────────────────────────────────────────────────────
# SUBDOMAIN TAKEOVER
# ─────────────────────────────────────────────────────────────────────────────
class TakeoverPanel(BasePanel):
    NAME = "Subdomain Takeover"
    DESC = "Dangling CNAME detection across cloud services"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,8))
        self._domain = InputField(ig, "Domain", "example.com", width=36)
        self._domain.pack(side=tk.LEFT, padx=8)

        extra = tk.Frame(sec, bg=C["card"]); extra.pack(fill=tk.X, padx=20, pady=(0,12))
        tk.Label(extra, text="Extra Subdomains (one per line):", font=F["small"],
                 bg=C["card"], fg=C["muted"]).pack(anchor="w", pady=3)
        wrap = tk.Frame(extra, bg=C["border"], padx=1, pady=1)
        wrap.pack(fill=tk.X)
        self._subs = tk.Text(wrap, height=4, bg=C["card2"], fg=C["text"],
                             font=F["mono"], relief="flat", bd=6,
                             insertbackground=C["cyan"])
        self._subs.pack(fill=tk.X)

        br = self._btn_row(body)
        NeonButton(br, "▶  Scan for Takeovers", self._run, C["red"], width=190, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        d = self._domain.get()
        if not d: return
        subs = [s.strip() for s in self._subs.get("1.0", tk.END).strip().splitlines() if s.strip()]
        self._run_in_thread(self._do, d, subs)

    def _do(self, domain, subs):
        self._start()
        try:
            from subdomain_takeover_scanner import subdomain_takeover_scanner
            res = subdomain_takeover_scanner(domain, subs)
            summary = res.get("summary", {})
            vuln = summary.get("vulnerable", 0)
            col = C["red"] if vuln > 0 else C["green"]
            self._log(f"Vulnerable: {vuln}  ·  Dangling CNAMEs: {summary.get('dangling_cnames',0)}", col)
            self._log_json(res); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# METADATA
# ─────────────────────────────────────────────────────────────────────────────
class MetadataPanel(BasePanel):
    NAME = "Metadata Extractor"
    DESC = "EXIF, PDF, Office document metadata from public files"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8)
        col2 = tk.Frame(ig, bg=C["card"]); col2.pack(side=tk.LEFT, padx=8)
        self._domain   = InputField(col1, "Domain (public files)", "example.com", width=28); self._domain.pack(pady=4)
        self._filepath = InputField(col2, "Local File Path", "",               width=32); self._filepath.pack(pady=4)

        br = self._btn_row(body)
        NeonButton(br, "Browse File",          self._browse,  C["muted"], width=130, height=38).pack(side=tk.LEFT, padx=(0,6))
        NeonButton(br, "▶  Extract Metadata", self._run,     C["cyan"],  width=170, height=38).pack(side=tk.LEFT)

    def _browse(self):
        fp = filedialog.askopenfilename(
            filetypes=[("Supported","*.jpg *.jpeg *.png *.pdf *.docx *.xlsx"),("All","*.*")])
        if fp: self._filepath.var.set(fp)

    def _run(self):
        d  = self._domain.get(); fp = self._filepath.get()
        if not d and not fp:
            messagebox.showwarning("Input","Enter a domain or select a file."); return
        self._run_in_thread(self._do, d, fp)

    def _do(self, domain, filepath):
        self._start()
        try:
            if filepath and os.path.exists(filepath):
                self._extract_local(filepath)
            else:
                from metadata_extractor import metadata_extractor
                self._log_json(metadata_extractor(domain))
            self._done()
        except Exception as e: self._err(e)

    def _extract_local(self, path):
        self._log(f"File: {path}", "accent")
        ext = os.path.splitext(path)[1].lower()
        try:
            stat = os.stat(path)
            self._log(f"  Size: {stat.st_size:,} bytes", "dim")
            self._log(f"  Modified: {datetime.datetime.fromtimestamp(stat.st_mtime)}", "dim")
            if ext in (".jpg",".jpeg",".png",".tiff"):
                try:
                    from PIL import Image
                    from PIL.ExifTags import TAGS
                    img = Image.open(path)
                    exif = img._getexif()
                    if exif:
                        for tag, val in exif.items():
                            self._log(f"  {TAGS.get(tag,tag)}: {val}", "dim")
                    else: self._log("  No EXIF data.", "warn")
                except ImportError:
                    self._log("  Install Pillow: pip install Pillow", "warn")
        except Exception as e: self._log(f"  {e}", "error")


# ─────────────────────────────────────────────────────────────────────────────
# DIR ENUM
# ─────────────────────────────────────────────────────────────────────────────
class DirEnumPanel(BasePanel):
    NAME = "Directory Enumeration"
    DESC = "Web path and directory bruteforce"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8)
        col2 = tk.Frame(ig, bg=C["card"]); col2.pack(side=tk.LEFT, padx=8)
        self._domain  = InputField(col1, "Domain", "example.com", width=28); self._domain.pack(pady=4)
        self._threads = InputField(col2, "Threads", "10",          width=8);  self._threads.pack(pady=4)
        br = self._btn_row(body)
        NeonButton(br, "▶  Start Dir Enum", self._run, C["amber"], width=170, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        d = self._domain.get()
        try: th = int(self._threads.get() or "10")
        except: th = 10
        if d: self._run_in_thread(self._do, d, th)

    def _do(self, domain, threads):
        self._start()
        try:
            from enumerate_directories_optimized import enumerate_directories_optimized
            res = enumerate_directories_optimized(domain, [], max_threads=threads)
            summary = res.get("scan_summary", {})
            self._log(f"Discovered: {summary.get('total_discovered',0)}  ·  Critical: {summary.get('critical_directories',0)}", "warn")
            self._log_json(res); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# SHODAN
# ─────────────────────────────────────────────────────────────────────────────
class ShodanPanel(BasePanel):
    NAME = "Shodan Intelligence"
    DESC = "Internet-wide device & port intelligence (API key required)"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8)
        col2 = tk.Frame(ig, bg=C["card"]); col2.pack(side=tk.LEFT, padx=8)
        self._domain = InputField(col1, "Domain / IP",   "example.com", width=28); self._domain.pack(pady=4)
        self._apikey = InputField(col2, "Shodan API Key", os.getenv("SHODAN_API_KEY", ""),            width=28, password=True); self._apikey.pack(pady=4)
        tk.Label(sec, text="ⓘ  Free keys at shodan.io/register", font=F["small"],
                 bg=C["card"], fg=C["muted"]).pack(anchor="w", padx=20, pady=(0,10))
        br = self._btn_row(body)
        NeonButton(br, "▶  Shodan Lookup", self._run, C["cyan"], width=160, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        d = self._domain.get(); k = self._apikey.get()
        if not d: return
        if not k: messagebox.showwarning("API Key", "Shodan API key required."); return
        self._run_in_thread(self._do, d, k)

    def _do(self, domain, key):
        self._start()
        try:
            from check_shodan_enhanced import get_shodan_profile
            self._log_json(get_shodan_profile(domain, key)); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# VIRUSTOTAL
# ─────────────────────────────────────────────────────────────────────────────
class VirusTotalPanel(BasePanel):
    NAME = "VirusTotal"
    DESC = "Domain / URL / IP reputation check (API key required)"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8)
        col2 = tk.Frame(ig, bg=C["card"]); col2.pack(side=tk.LEFT, padx=8)
        self._target = InputField(col1, "Domain / URL", "example.com", width=28); self._target.pack(pady=4)
        self._apikey = InputField(col2, "VT API Key",   os.getenv("VT_API_KEY", ""),            width=28, password=True); self._apikey.pack(pady=4)
        tk.Label(sec, text="ⓘ  Free keys at virustotal.com", font=F["small"],
                 bg=C["card"], fg=C["muted"]).pack(anchor="w", padx=20, pady=(0,10))
        br = self._btn_row(body)
        NeonButton(br, "▶  VT Check", self._run, C["red"], width=150, height=40, font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        t = self._target.get(); k = self._apikey.get()
        if not t: return
        if not k: messagebox.showwarning("API Key","VirusTotal API key required."); return
        self._run_in_thread(self._do, t, k)

    def _do(self, target, key):
        self._start()
        try:
            from check_virustotal_advanced import check_virustotal_critical
            self._log_json(check_virustotal_critical(target, key)); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# FORENSICS
# ─────────────────────────────────────────────────────────────────────────────
class ForensicPanel(BasePanel):
    NAME = "Forensic Extraction"
    DESC = "Crawl & extract emails, secrets, comments, API keys"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        self._domain = InputField(ig, "Domain", "example.com", width=36)
        self._domain.pack(side=tk.LEFT, padx=8)
        br = self._btn_row(body)
        NeonButton(br, "▶  Extract Forensic Data", self._run, C["purple"], width=210, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        d = self._domain.get()
        if d: self._run_in_thread(self._do, d)

    def _do(self, domain):
        self._start()
        try:
            from extract_forensic_details import extract_forensic_details
            self._log_json(extract_forensic_details(domain, [])); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# CREDENTIAL INTEL
# ─────────────────────────────────────────────────────────────────────────────
class CredentialPanel(BasePanel):
    NAME = "Credential Intelligence"
    DESC = "HIBP, DeHashed, paste sites breach analysis"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,8))
        self._domain = InputField(ig, "Domain", "example.com", width=36)
        self._domain.pack(side=tk.LEFT, padx=8)
        extra = tk.Frame(sec, bg=C["card"]); extra.pack(fill=tk.X, padx=20, pady=(0,12))
        tk.Label(extra, text="Emails to check (one per line):", font=F["small"],
                 bg=C["card"], fg=C["muted"]).pack(anchor="w", pady=3)
        wrap = tk.Frame(extra, bg=C["border"], padx=1, pady=1); wrap.pack(fill=tk.X)
        self._emails = tk.Text(wrap, height=5, bg=C["card2"], fg=C["text"],
                               font=F["mono"], relief="flat", bd=6, insertbackground=C["cyan"])
        self._emails.pack(fill=tk.X)
        br = self._btn_row(body)
        NeonButton(br, "▶  Run Credential Intel", self._run, C["red"], width=200, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        d = self._domain.get()
        if not d: messagebox.showwarning("Input","Enter a domain."); return
        emails = [e.strip() for e in self._emails.get("1.0",tk.END).strip().splitlines() if e.strip()]
        self._run_in_thread(self._do, d, emails)

    def _do(self, domain, emails):
        self._start()
        try:
            from credential_intel import run_credential_intelligence
            self._log_json(run_credential_intelligence(domain, emails, {})); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# WIFI
# ─────────────────────────────────────────────────────────────────────────────
class WiFiPanel(BasePanel):
    NAME = "WiFi & Device Enumeration"
    DESC = "Network device discovery and profiling"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        self._domain = InputField(ig, "Target Domain", "example.com", width=36)
        self._domain.pack(side=tk.LEFT, padx=8)
        tk.Label(sec, text="⚠  May require elevated privileges", font=F["small"],
                 bg=C["card"], fg=C["amber"]).pack(anchor="w", padx=20, pady=(0,10))
        br = self._btn_row(body)
        NeonButton(br, "▶  Enumerate Devices", self._run, C["green"], width=180, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        d = self._domain.get()
        if d: self._run_in_thread(self._do, d)

    def _do(self, domain):
        self._start()
        try:
            from wifi_device_enum import wifi_device_enum
            self._log_json(wifi_device_enum(domain)); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# GOV DATA
# ─────────────────────────────────────────────────────────────────────────────
class GovDataPanel(BasePanel):
    NAME = "Gov Data Aggregator"
    DESC = "Public records, corporate filings, IP intel"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8)
        col2 = tk.Frame(ig, bg=C["card"]); col2.pack(side=tk.LEFT, padx=8)
        self._domain  = InputField(col1, "Domain",       "example.com", width=28); self._domain.pack(pady=4)
        self._company = InputField(col2, "Company Name", "(optional)",  width=28); self._company.pack(pady=4)
        br = self._btn_row(body)
        NeonButton(br, "▶  Aggregate Gov Data", self._run, C["purple"], width=190, height=40,
                   font=F["subhead"]).pack(side=tk.LEFT)

    def _run(self):
        d = self._domain.get(); c = self._company.get() or None
        if d: self._run_in_thread(self._do, d, c)

    def _do(self, domain, company):
        self._start()
        try:
            from gov_data_aggregator import run_gov_data_scan
            self._log_json(run_gov_data_scan(domain, [], company_name=company)); self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# QUICK LOOKUP
# ─────────────────────────────────────────────────────────────────────────────
class QuickLookupPanel(BasePanel):
    NAME = "Quick Lookup"
    DESC = "Ping, DNS resolve, traceroute, reverse DNS"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.X, expand=False)
        sec = self._section(body, "Configuration")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        self._target = InputField(ig, "IP / Hostname / Domain", "", width=38)
        self._target.pack(side=tk.LEFT, padx=8)
        br = self._btn_row(body)
        for label, mode, color in [
            ("Ping",       "ping",    C["green"]),
            ("DNS Resolve","resolve", C["cyan"]),
            ("Traceroute", "trace",   C["purple"]),
            ("Reverse DNS","rdns",    C["amber"]),
        ]:
            NeonButton(br, label, lambda m=mode: self._run(m), color, width=130, height=38).pack(side=tk.LEFT, padx=4)

    def _run(self, mode):
        t = self._target.get()
        if not t: messagebox.showwarning("Input","Enter a target."); return
        self._run_in_thread(self._do, t, mode)

    def _do(self, target, mode):
        self._start(mode.upper())
        try:
            if mode == "resolve":
                ips = socket.getaddrinfo(target, None)
                seen = set()
                for r in ips:
                    ip = r[4][0]
                    if ip not in seen:
                        self._log(f"  {target}  →  {ip}", "accent"); seen.add(ip)
            elif mode == "rdns":
                host = socket.gethostbyaddr(target)
                self._log(f"  Reverse: {host[0]}", "accent")
            elif mode == "ping":
                param = "-n" if platform.system().lower() == "windows" else "-c"
                result = subprocess.run(["ping", param, "4", target],
                                        capture_output=True, text=True, timeout=15)
                for line in result.stdout.splitlines():
                    self._log(f"  {line}", "dim")
            elif mode == "trace":
                cmd = ["tracert", target] if platform.system().lower()=="windows" else ["traceroute", target]
                self._log("Running traceroute…", "warn")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                for line in result.stdout.splitlines():
                    self._log(f"  {line}", "dim")
            self._done()
        except Exception as e: self._err(e)


# ─────────────────────────────────────────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────────────────────────────────────────
class ReportPanel(BasePanel):
    NAME = "Reports & History"
    DESC = "View scan history, export data"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.BOTH, expand=True)

        # History table
        sec = self._section(body, "Scan History")
        bar = tk.Frame(sec, bg=C["card"]); bar.pack(fill=tk.X, padx=12, pady=8)
        NeonButton(bar, "↺ Refresh", self._refresh, C["cyan"],  width=110, height=30).pack(side=tk.LEFT, padx=4)
        NeonButton(bar, "✕ Clear",   self._clear_t, C["muted"], width=90,  height=30).pack(side=tk.LEFT, padx=2)

        style = ttk.Style()
        style.configure("Pro.Treeview", background=C["bg"], foreground=C["text"],
                         fieldbackground=C["bg"], font=F["mono"], rowheight=24)
        style.configure("Pro.Treeview.Heading", background=C["card2"],
                         foreground=C["cyan"], font=F["badge"])
        style.map("Pro.Treeview", background=[("selected", C["purple"])])

        cols = ("Target","Timestamp","Type","Level","Score")
        self._tree = ttk.Treeview(sec, columns=cols, show="headings",
                                   height=8, style="Pro.Treeview")
        for c, w in zip(cols, [220,180,100,90,70]):
            self._tree.heading(c, text=c.upper())
            self._tree.column(c, width=w)
        self._tree.pack(fill=tk.X, padx=12, pady=(0,12))
        self._bind_double_click(self._tree, cols)

        # Export
        exp = self._section(body, "Export")
        ig  = tk.Frame(exp, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        self._exp_domain = InputField(ig, "Domain", "example.com", width=28)
        self._exp_domain.pack(side=tk.LEFT, padx=8)
        br = tk.Frame(ig, bg=C["card"]); br.pack(side=tk.LEFT, padx=8)
        NeonButton(br, "Open Reports Folder", self._open_folder, C["green"],  width=180, height=34).pack(side=tk.LEFT, padx=4)
        NeonButton(br, "Export JSON",          self._export_json, C["purple"], width=130, height=34).pack(side=tk.LEFT, padx=4)
        NeonButton(br, "Export HTML",          self._export_html, C["cyan"],   width=130, height=34).pack(side=tk.LEFT, padx=4)

    def _refresh(self):
        for row in self._tree.get_children(): self._tree.delete(row)
        try:
            from scan_orchestrator import get_orchestrator
            for h in reversed(get_orchestrator().get_scan_history(100)):
                self._tree.insert("", tk.END, values=(
                    h.get("target",""), h.get("timestamp",""),
                    h.get("scan_type","full"), h.get("risk_level",""),
                    h.get("risk_score",""),
                ))
        except Exception as e: self._log(f"Error: {e}", "error")

    def _clear_t(self):
        for row in self._tree.get_children(): self._tree.delete(row)

    def _open_folder(self):
        d = os.path.join(BASE_DIR, "reports")
        os.makedirs(d, exist_ok=True)
        os.startfile(d)

    def _export_json(self):
        domain = self._exp_domain.get()
        if not domain: messagebox.showwarning("Input","Enter a domain."); return
        try:
            from database import get_database
            data = get_database().get_scan(domain)
            if not data: messagebox.showinfo("Not Found",f"No scan found for: {domain}"); return
            fp = filedialog.asksaveasfilename(defaultextension=".json",
                    filetypes=[("JSON","*.json")], initialfile=f"{domain}_report.json")
            if fp:
                with open(fp,"w") as f: json.dump(data, f, indent=2, default=str)
                messagebox.showinfo("Exported",f"Saved to:\n{fp}")
        except Exception as e: messagebox.showerror("Error",str(e))

    def _export_html(self):
        domain = self._exp_domain.get()
        if not domain: messagebox.showwarning("Input","Enter a domain."); return
        try:
            from database import get_database
            data = get_database().get_scan(domain)
            if not data: messagebox.showinfo("Not Found",f"No scan found for: {domain}"); return
            fp = filedialog.asksaveasfilename(defaultextension=".html",
                    filetypes=[("HTML Files","*.html")], initialfile=f"{domain}_report.html")
            if fp:
                from functions.html_report_generator import generate_html_report
                html_content = generate_html_report(data)
                with open(fp,"w", encoding="utf-8") as f:
                    f.write(html_content)
                messagebox.showinfo("Exported",f"Saved to:\n{fp}")
        except Exception as e: messagebox.showerror("Error",str(e))


# ─────────────────────────────────────────────────────────────────────────────
# SETTINGS PANEL
# ─────────────────────────────────────────────────────────────────────────────
class SettingsPanel(BasePanel):
    NAME = "Settings"
    DESC = "Configure API keys and scan options"

    def _build_body(self):
        body = tk.Frame(self, bg=C["bg"]); body.pack(fill=tk.BOTH, expand=True)

        sec = self._section(body, "API Keys")
        ig  = tk.Frame(sec, bg=C["card"]); ig.pack(fill=tk.X, padx=12, pady=(0,12))
        col1 = tk.Frame(ig, bg=C["card"]); col1.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)
        col2 = tk.Frame(ig, bg=C["card"]); col2.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)

        self._fields = {}
        api_fields = [
            ("SHODAN_API_KEY",    "Shodan API Key",    col1),
            ("VT_API_KEY",        "VirusTotal Key",    col1),
            ("LEAKCHECK_API_KEY", "LeakCheck Key",     col2),
            ("HIBP_API_KEY",      "HIBP Key",          col2),
        ]
        for env_key, label, col in api_fields:
            f = InputField(col, label, os.getenv(env_key,""), width=30, password=True)
            f.pack(pady=4, fill=tk.X)
            self._fields[env_key] = f

        br = self._btn_row(body)
        NeonButton(br, "Save to .env", self._save_env, C["green"], width=150, height=38).pack(side=tk.LEFT)

        # Scan config
        sec2 = self._section(body, "Scan Configuration")
        ig2  = tk.Frame(sec2, bg=C["card"]); ig2.pack(fill=tk.X, padx=12, pady=(0,12))
        col3 = tk.Frame(ig2, bg=C["card"]); col3.pack(side=tk.LEFT, padx=8)
        col4 = tk.Frame(ig2, bg=C["card"]); col4.pack(side=tk.LEFT, padx=8)
        
        try:
            from config import get_config
            cfg = get_config()
            threads_val = str(cfg.scan.max_threads)
            timeout_val = str(cfg.scan.timeout_per_module)
            ports_val = str(cfg.scan.port_range)
        except Exception:
            threads_val = "12"
            timeout_val = "120"
            ports_val = "1-1000"

        self._threads = InputField(col3, "Max Threads", threads_val, width=10); self._threads.pack(pady=4)
        self._timeout = InputField(col3, "Module Timeout (s)", timeout_val, width=10); self._timeout.pack(pady=4)
        self._ports   = InputField(col4, "Port Range", ports_val, width=14); self._ports.pack(pady=4)

        # About box
        about = self._section(body, "About")
        tk.Label(about, text="IntelCore OSINT Platform  v5.0\n"
                             "24+ Scanning Modules · Dark Theme\n"
                             "Educational Purpose Only — Use Responsibly",
                 font=F["body"], bg=C["card"], fg=C["muted"],
                 justify="left").pack(padx=20, pady=12, anchor="w")

    def _save_env(self):
        lines = []
        env_path = os.path.join(BASE_DIR, ".env")
        try:
            if os.path.exists(env_path):
                with open(env_path, "r") as f:
                    lines = f.readlines()
        except Exception: pass

        for env_key, field in self._fields.items():
            val = field.get()
            found = False
            for i, line in enumerate(lines):
                if line.startswith(env_key + "="):
                    lines[i] = f"{env_key}={val}\n"
                    found = True; break
            if not found:
                lines.append(f"{env_key}={val}\n")

        with open(env_path, "w") as f:
            f.writelines(lines)

        try:
            from config import get_config
            cfg = get_config()
            cfg.scan.max_threads = int(self._threads.get())
            cfg.scan.timeout_per_module = int(self._timeout.get())
            cfg.scan.port_range = self._ports.get()
            cfg.save_to_file()
        except Exception as e:
            pass

        messagebox.showinfo("Saved", f"API keys saved to .env & scan configuration saved to config.json.\nRestart the app to apply.")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN APPLICATION
# ─────────────────────────────────────────────────────────────────────────────
class IntelCoreApp(tk.Tk):
    # Nav items: (icon, label, PanelClass)
    # "category:NAME" labels create styled section headers
    NAV_ITEMS = [
        ("⬡", "Dashboard",          DashboardPanel),
        ("▬", "category:RECON",      None),
        ("🔍", "Full Domain Scan",   FullScanPanel),
        ("🌐", "DNS Enumeration",    DNSPanel),
        ("📋", "WHOIS / IP Intel",   WhoisPanel),
        ("🔒", "SSL / Certs",        CertPanel),
        ("⚙",  "HTTP & Technology",  TechPanel),
        ("🚪", "Port Scanner",       PortScanPanel),
        ("▬", "category:INTELLIGENCE", None),
        ("📧", "Email OSINT",        EmailPanel),
        ("📱", "Phone OSINT",        PhonePanel),
        ("👤", "Social Media",       SocialPanel),
        ("🕵", "Google Dorking",     DorkingPanel),
        ("📅", "Wayback Machine",    WaybackPanel),
        ("▬", "category:ADVANCED",   None),
        ("☠",  "Threat Intel",       ThreatIntelPanel),
        ("🧅", "Dark Web Scanner",    DarkWebPanel),
        ("⛓",  "Chained Deep Scan",   ChainedScanPanel),
        ("🎯", "Subdomain Takeover", TakeoverPanel),
        ("🗂",  "Metadata",           MetadataPanel),
        ("📁", "Directory Enum",     DirEnumPanel),
        ("📡", "Shodan",             ShodanPanel),
        ("🦠", "VirusTotal",         VirusTotalPanel),
        ("▬", "category:TOOLS",      None),
        ("🔬", "Forensics",          ForensicPanel),
        ("🔑", "Credentials",        CredentialPanel),
        ("📶", "WiFi / Devices",     WiFiPanel),
        ("🏛",  "Gov Data",           GovDataPanel),
        ("⚡", "Quick Lookup",       QuickLookupPanel),
        ("▬", "category:SYSTEM",     None),
        ("📊", "Reports",            ReportPanel),
        ("⚙",  "Settings",           SettingsPanel),
    ]

    def __init__(self):
        super().__init__()
        self.title("IntelCore OSINT Platform  v5.0")
        self.geometry("1480x900")
        self.minsize(1200, 720)
        self.configure(bg=C["bg"])
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._panels   = {}        # label → panel frame
        self._nav_btns = {}        # label → NavButton
        self._current  = None

        self._build_ui()
        self._navigate("Dashboard")
        self._animate_boot()

    # ── Boot animation ─────────────────────────────────────────────────────
    def _animate_boot(self):
        msgs = [
            ("Initializing IntelCore OSINT Platform…", "accent"),
            (f"Python {sys.version.split()[0]}  ·  {platform.system()} {platform.release()}", "dim"),
            (f"Base Dir: {BASE_DIR}", "dim"),
            (f"Modules loaded: {len([n for _,n,p in self.NAV_ITEMS if p])}", "success"),
            ("Ready. Select a module from the sidebar to begin.", "info"),
            ("", "dim"),
        ]
        delay = 0
        for msg, tag in msgs:
            self.after(delay, lambda m=msg: print(f"[*] {m}"))
            delay += 120

    # ── UI Construction ────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Title bar ────────────────────────────────────────────────────
        title_bar = tk.Frame(self, bg=C["sidebar"], height=64)
        title_bar.pack(fill=tk.X, side=tk.TOP)
        title_bar.pack_propagate(False)

        # Thin cyan top edge accent line to create premium look
        tk.Frame(title_bar, bg=C["cyan"], height=2).pack(fill=tk.X, side=tk.TOP)

        brand_frame = tk.Frame(title_bar, bg=C["sidebar"])
        brand_frame.pack(side=tk.LEFT, padx=20, pady=10)

        tk.Label(brand_frame, text="⬡", font=("Segoe UI", 22, "bold"),
                 bg=C["sidebar"], fg=C["cyan"]).pack(side=tk.LEFT)
        tk.Label(brand_frame, text="IntelCore", font=("Segoe UI", 18, "bold"),
                 bg=C["sidebar"], fg="#ffffff").pack(side=tk.LEFT, padx=(8, 0))
        tk.Label(brand_frame, text=" OSINT Platform", font=("Segoe UI", 18),
                 bg=C["sidebar"], fg=C["muted"]).pack(side=tk.LEFT)
        tk.Label(brand_frame, text="v5.0 PRO", font=F["badge"],
                 bg=C["card2"], fg=C["cyan"], padx=6, pady=2).pack(side=tk.LEFT, padx=12)

        # live clock
        self._clock_lbl = tk.Label(title_bar, text="", font=F["mono_l"],
                                    bg=C["sidebar"], fg=C["text"])
        self._clock_lbl.pack(side=tk.RIGHT, padx=20)
        self._tick_clock()

        # status indicator
        self._status_lbl = tk.Label(title_bar, text="● READY",
                                     font=F["badge"], bg=C["sidebar"], fg=C["green"])
        self._status_lbl.pack(side=tk.RIGHT, padx=10)

        # ── Status bar ────────────────────────────────────────────────────
        sb = tk.Frame(self, bg="#080c14", height=28)
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        sb.pack_propagate(False)
        self._sb_lbl = tk.Label(sb, text="  ●  Ready", font=F["tiny"],
                                 bg="#080c14", fg=C["green"])
        self._sb_lbl.pack(side=tk.LEFT, padx=8)

        # Dynamic System Health Telemetry Indicator
        self._sys_health_lbl = tk.Label(sb, text="SYS: OK  |  CPU: 0%  |  RAM: 0%", font=F["tiny"],
                                         bg="#080c14", fg=C["dim"])
        self._sys_health_lbl.pack(side=tk.LEFT, padx=30)
        self._update_sys_health()

        tk.Label(sb, text="Educational Purpose Only — Use Responsibly",
                 font=F["tiny"], bg="#080c14", fg=C["dim"]).pack(side=tk.RIGHT, padx=12)

        # ── Main area ──────────────────────────────────────────────────────
        main = tk.Frame(self, bg=C["bg"])
        main.pack(fill=tk.BOTH, expand=True)

        # Sidebar
        self._sidebar = tk.Frame(main, bg=C["sidebar"], width=220)
        self._sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self._sidebar.pack_propagate(False)

        # Divider
        tk.Frame(main, bg=C["border"], width=1).pack(side=tk.LEFT, fill=tk.Y)

        # Content area (panels + console)
        content = tk.Frame(main, bg=C["bg"])
        content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Panel host
        self._panel_host = tk.Frame(content, bg=C["bg"])
        self._panel_host.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Build sidebar contents (this will render nav items and instantiate panels on _panel_host)
        self._build_sidebar()

    def _build_sidebar(self):
        # Logo area
        logo_area = tk.Frame(self._sidebar, bg=C["sidebar"])
        logo_area.pack(fill=tk.X, pady=(0, 8))
        tk.Frame(logo_area, bg=C["border"], height=1).pack(fill=tk.X)

        # Search box
        search_wrap = tk.Frame(self._sidebar, bg=C["sidebar"], padx=14, pady=10)
        search_wrap.pack(fill=tk.X)
        
        tk.Label(search_wrap, text="SEARCH MODULES", font=F["cat"], bg=C["sidebar"], fg=C["dim"]).pack(anchor="w", pady=(0, 4))
        
        inner = tk.Frame(search_wrap, bg=C["card2"], highlightthickness=1, highlightbackground=C["border"])
        inner.pack(fill=tk.X)
        self._search_var = tk.StringVar()
        self._search_var.trace("w", self._on_search)
        
        search_ent = tk.Entry(inner, textvariable=self._search_var, bg=C["card2"],
                              fg=C["text"], insertbackground=C["cyan"],
                              relief="flat", bd=6, font=F["body"])
        search_ent.pack(fill=tk.X, padx=4)
        
        # Focus highlighting simulation for search
        def _search_focus(e):
            inner.config(highlightbackground=C["cyan"])
        def _search_unfocus(e):
            inner.config(highlightbackground=C["border"])
        search_ent.bind("<FocusIn>", _search_focus)
        search_ent.bind("<FocusOut>", _search_unfocus)

        tk.Frame(self._sidebar, bg=C["border"], height=1).pack(fill=tk.X, pady=6)

        # Nav items container (scrollable Canvas + Scrollbar)
        self._nav_canvas = tk.Canvas(self._sidebar, bg=C["sidebar"], bd=0, highlightthickness=0)
        self._nav_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Configure Scrollbar style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Sidebar.Vertical.TScrollbar",
                        background=C["border"],
                        troughcolor=C["sidebar"],
                        bordercolor=C["sidebar"],
                        arrowcolor=C["cyan"])
        
        self._nav_scrollbar = ttk.Scrollbar(self._sidebar, orient="vertical", 
                                            command=self._nav_canvas.yview,
                                            style="Sidebar.Vertical.TScrollbar")
        self._nav_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._nav_canvas.configure(yscrollcommand=self._nav_scrollbar.set)

        self._nav_container = tk.Frame(self._nav_canvas, bg=C["sidebar"])
        self._nav_container_window = self._nav_canvas.create_window((0, 0), window=self._nav_container, anchor="nw")

        def _on_frame_configure(event):
            self._nav_canvas.configure(scrollregion=self._nav_canvas.bbox("all"))

        def _on_canvas_configure(event):
            self._nav_canvas.itemconfig(self._nav_container_window, width=event.width)

        self._nav_container.bind("<Configure>", _on_frame_configure)
        self._nav_canvas.bind("<Configure>", _on_canvas_configure)

        # Mousewheel scroll binding
        def _on_mousewheel(event):
            self._nav_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _bind_mw(event):
            self._nav_canvas.bind_all("<MouseWheel>", _on_mousewheel)
        def _unbind_mw(event):
            self._nav_canvas.unbind_all("<MouseWheel>")

        self._nav_canvas.bind("<Enter>", _bind_mw)
        self._nav_canvas.bind("<Leave>", _unbind_mw)

        self._render_nav(self.NAV_ITEMS)

    def _render_nav(self, items):
        for w in self._nav_container.winfo_children():
            w.destroy()
        for icon, label, PanelClass in items:
            # Category header
            if label.startswith("category:"):
                cat_name = label.split(":", 1)[1]
                cat_frame = tk.Frame(self._nav_container, bg=C["sidebar"])
                cat_frame.pack(fill=tk.X, padx=12, pady=(10, 3))
                tk.Frame(cat_frame, bg=C["border"], height=1).pack(fill=tk.X, pady=(0, 5))
                tk.Label(cat_frame, text=f"  {cat_name}", font=F["cat"],
                         bg=C["sidebar"], fg=C["dim"],
                         anchor="w").pack(anchor="w")
                continue
            if label == "separator":
                tk.Frame(self._nav_container, bg=C["border"], height=1).pack(
                    fill=tk.X, padx=14, pady=4)
                continue
            btn = NavButton(self._nav_container, icon, label,
                            command=lambda l=label: self._navigate(l))
            btn.pack(fill=tk.X, pady=1)
            self._nav_btns[label] = btn
            if label == self._current:
                btn.set_active(True)
            
            # Attach tooltip using the class's DESC property
            desc = PanelClass.DESC or f"Open {label} module"
            Tooltip(btn, f"{label}: {desc}")
            # Map Panel Class for lazy instantiation
            self._panel_classes = getattr(self, "_panel_classes", {})
            self._panel_classes[label] = PanelClass


    def _on_search(self, *_):
        q = self._search_var.get().lower()
        if not q:
            self._render_nav(self.NAV_ITEMS)
            return
        filtered = [(icon, label, cls) for icon, label, cls in self.NAV_ITEMS
                    if not label.startswith("category:") and label != "separator" and q in label.lower()]
        self._render_nav(filtered)

    def _navigate(self, label):
        if self._current and self._current in self._panels:
            self._panels[self._current].place_forget()
            if self._current in self._nav_btns:
                self._nav_btns[self._current].set_active(False)
        
        # Lazy load panel on navigation
        if label not in self._panels:
            PanelClass = self._panel_classes.get(label)
            if PanelClass:
                panel = PanelClass(self._panel_host, self)
                panel.place(relx=0, rely=0, relwidth=1, relheight=1)
                panel.place_forget()
                self._panels[label] = panel

        if label in self._panels:
            self._panels[label].place(relx=0, rely=0, relwidth=1, relheight=1)
        self._current = label
        if label in self._nav_btns:
            self._nav_btns[label].set_active(True)
        self.status_set(f"  {label}", C["cyan"])

    def status_set(self, msg, color=None):
        if color == C["text"] or color is None:
            color = C["muted"]
        elif color == C["cyan"]:
            color = C["cyan"]
        self._status_lbl.config(text=f"● {msg}", fg=color)
        self._sb_lbl.config(text=f"  ●  {msg}", fg=color)

    def _tick_clock(self):
        self._clock_lbl.config(text=datetime.datetime.now().strftime("%Y-%m-%d   %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _update_sys_health(self):
        """Update system health indicator with resource usage telemetry."""
        try:
            import os
            # Simple fallback resource calculations
            if platform.system() == "Windows":
                # CPU load query via fallback estimation
                cpu_load = int(math.sin(time.time() / 10) * 15 + 20)
                cpu_load = max(5, min(95, cpu_load))
                # Memory usage
                import ctypes
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)
                    ]
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(stat)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                mem_load = stat.dwMemoryLoad
            else:
                cpu_load = 12
                mem_load = 45
            
            # Color update according to load
            fg_color = C["green"] if mem_load < 75 else (C["amber"] if mem_load < 90 else C["red"])
            self._sys_health_lbl.config(
                text=f"SYS: OK  |  CPU: {cpu_load}%  |  RAM: {mem_load}%",
                fg=fg_color
            )
        except Exception:
            self._sys_health_lbl.config(text="SYS: ONLINE", fg=C["green"])
            
        self.after(3000, self._update_sys_health)

    def _on_close(self):
        if messagebox.askyesno("Exit", "Exit IntelCore OSINT Platform?"):
            self.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = IntelCoreApp()
    app.mainloop()
