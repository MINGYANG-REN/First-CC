"""
本地密码管理器 — 加密存储你的账号密码，数据不上传网络
"""
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
import base64
import os
import sv_ttk
from cryptography.fernet import Fernet
import sys

# ========== 配色方案 ==========
COLORS = {
    "primary": "#4F46E5",
    "primary_hover": "#4338CA",
    "surface": "#F1F5F9",
    "card": "#FFFFFF",
    "text": "#1E293B",
    "text_secondary": "#64748B",
    "danger": "#EF4444",
    "success": "#10B981",
    "border": "#E2E8F0",
}
FONT = ("Microsoft YaHei", 10)
FONT_TITLE = ("Microsoft YaHei", 16, "bold")
FONT_MONO = ("Consolas", 11)

# ========== 数据库和加密核心 ==========
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "passwords.db")

# 固定加密密钥（本地存储，保护数据库文件不被直接查看）
_FIXED_KEY = base64.urlsafe_b64encode(hashlib.sha256(b"password-manager-local-key-v1").digest())


class PasswordManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_tables()
        self._fernet = Fernet(_FIXED_KEY)

    def _init_tables(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                account TEXT NOT NULL,
                encrypted_password BLOB NOT NULL
            )
        """)
        self.conn.commit()

    def add_account(self, platform: str, account: str, password: str):
        enc = self._fernet.encrypt(password.encode("utf-8"))
        self.conn.execute(
            "INSERT INTO accounts(platform, account, encrypted_password) VALUES(?,?,?)",
            (platform, account, enc),
        )
        self.conn.commit()

    def delete_account(self, account_id: int):
        self.conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        self.conn.commit()

    def get_accounts(self, keyword: str = "") -> list:
        if keyword:
            rows = self.conn.execute(
                "SELECT id, platform, account, encrypted_password FROM accounts WHERE platform LIKE ? ORDER BY id DESC",
                (f"%{keyword}%",),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT id, platform, account, encrypted_password FROM accounts ORDER BY id DESC"
            ).fetchall()
        result = []
        for row in rows:
            try:
                plain = self._fernet.decrypt(row[3]).decode("utf-8")
            except Exception:
                plain = "[解密失败]"
            result.append((row[0], row[1], row[2], plain))
        return result

    def close(self):
        self.conn.close()


# ========== 图形界面 ==========

class PasswordApp:
    def __init__(self):
        self.manager = PasswordManager()
        self.root = tk.Tk()
        self.root.title("我的密码管理器")
        self.root.configure(bg=COLORS["surface"])

        # 窗口图标
        icon_path = os.path.join(APP_DIR, "icon.ico")
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)

        # 应用 Sun Valley 现代主题
        sv_ttk.set_theme("light")

        # 自定义样式
        style = ttk.Style()
        style.configure("Title.TLabel", font=FONT_TITLE, foreground=COLORS["primary"], background=COLORS["card"])
        style.configure("Card.TFrame", background=COLORS["card"])
        style.configure("Primary.TButton", font=FONT)
        style.map("Primary.TButton",
                  background=[("active", COLORS["primary_hover"]), ("!active", COLORS["primary"])])
        style.configure("Danger.TButton", font=FONT)

        self._show_main()
        self.root.mainloop()

    # ========== 主界面 ==========
    def _show_main(self):
        self.root.resizable(True, True)
        w, h = 640, 530
        x = (self.root.winfo_screenwidth() - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

        # 顶部导航栏
        nav = ttk.Frame(self.root, padding=(20, 14), style="Card.TFrame")
        nav.pack(fill="x")

        ttk.Label(nav, text="我的密码管理器", font=FONT_TITLE, foreground=COLORS["primary"],
                  background=COLORS["card"]).pack(side="left")

        ttk.Button(nav, text="+ 添加账号", command=self._add_dialog,
                   style="Primary.TButton").pack(side="right")
        ttk.Button(nav, text="↻ 刷新", command=lambda: self._refresh_list()).pack(side="right", padx=(0, 8))

        # 搜索栏
        search_bar = ttk.Frame(self.root, padding=(20, 6, 20, 8))
        search_bar.pack(fill="x")

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_bar, textvariable=self.search_var, font=FONT)
        search_entry.pack(fill="x")
        search_entry.insert(0, "")
        self.search_var.trace_add("write", lambda *_: self._refresh_list(self.search_var.get()))

        # 账号列表
        list_frame = ttk.Frame(self.root)
        list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 8))

        columns = ("platform", "account")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="browse", height=10)
        self.tree.heading("platform", text="平台")
        self.tree.heading("account", text="账号")
        self.tree.column("platform", width=200)
        self.tree.column("account", width=260)

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 详情区
        detail = ttk.Frame(self.root, padding=(20, 0, 20, 16))
        detail.pack(fill="x")

        ttk.Label(detail, text="密码", font=FONT, foreground=COLORS["text_secondary"]).pack(side="left")

        self.pwd_var = tk.StringVar()
        self.pwd_visible = False
        self.current_pwd = ""

        pwd_display = ttk.Label(detail, textvariable=self.pwd_var, font=FONT_MONO,
                                foreground=COLORS["text"], anchor="w", relief="solid", width=26)
        pwd_display.pack(side="left", padx=(8, 8))

        def toggle_pwd():
            self.pwd_visible = not self.pwd_visible
            self._update_pwd_display()
            eye_btn.config(text="🙈 隐藏" if self.pwd_visible else "👁 显示")

        eye_btn = ttk.Button(detail, text="👁 显示", command=toggle_pwd, width=8)
        eye_btn.pack(side="left", padx=(0, 10))

        ttk.Button(detail, text="📋 复制", command=self._copy_pwd).pack(side="left", padx=(0, 24))
        ttk.Button(detail, text="🗑 删除", command=self._delete_selected, style="Danger.TButton").pack(side="right")

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda e: self._copy_pwd())

        self._refresh_list()

    def _refresh_list(self, keyword=""):
        for item in self.tree.get_children():
            self.tree.delete(item)
        accounts = self.manager.get_accounts(keyword)
        self._accounts = {str(acc[0]): acc for acc in accounts}
        for acc in accounts:
            self.tree.insert("", "end", iid=str(acc[0]), values=(acc[1], acc[2]))
        self.pwd_var.set("")
        self.current_pwd = ""

    def _on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        acc = self._accounts.get(sel[0])
        if acc:
            self.current_pwd = acc[3]
            self._update_pwd_display()

    def _update_pwd_display(self):
        if self.pwd_visible:
            self.pwd_var.set(self.current_pwd)
        else:
            self.pwd_var.set("●" * len(self.current_pwd) if self.current_pwd else "")

    def _copy_pwd(self):
        if self.current_pwd:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.current_pwd)
            messagebox.showinfo("提示", "密码已复制到剪贴板")

    def _delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择一条记录")
            return
        if messagebox.askyesno("确认删除", "确定要删除这条记录吗？"):
            self.manager.delete_account(int(sel[0]))
            self._refresh_list()

    def _add_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("添加账号")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=COLORS["surface"])

        w, h = 380, 250
        x = self.root.winfo_x() + (self.root.winfo_width() - w) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - h) // 2
        dialog.geometry(f"{w}x{h}+{x}+{y}")

        card = ttk.Frame(dialog, padding=24)
        card.pack(fill="both", expand=True, padx=12, pady=12)

        ttk.Label(card, text="平台名称", font=FONT).grid(row=0, column=0, sticky="w", pady=(0, 2))
        plat = ttk.Entry(card, font=FONT)
        plat.grid(row=0, column=1, pady=(0, 10), sticky="ew", padx=(12, 0))

        ttk.Label(card, text="账号", font=FONT).grid(row=1, column=0, sticky="w", pady=(0, 2))
        acct = ttk.Entry(card, font=FONT)
        acct.grid(row=1, column=1, pady=(0, 10), sticky="ew", padx=(12, 0))

        ttk.Label(card, text="密码", font=FONT).grid(row=2, column=0, sticky="w", pady=(0, 2))
        pwd_frame = ttk.Frame(card)
        pwd_frame.grid(row=2, column=1, pady=(0, 16), sticky="ew", padx=(12, 0))
        pwd = ttk.Entry(pwd_frame, font=FONT_MONO, show="●")
        pwd.pack(side="left", fill="x", expand=True)

        def toggle_add_pwd():
            if pwd.cget("show") == "●":
                pwd.config(show="")
                add_eye.config(text="🙈")
            else:
                pwd.config(show="●")
                add_eye.config(text="👁")

        add_eye = ttk.Button(pwd_frame, text="👁", command=toggle_add_pwd, width=4)
        add_eye.pack(side="left", padx=(4, 0))

        card.columnconfigure(1, weight=1)

        def save():
            p, a, pw = plat.get().strip(), acct.get().strip(), pwd.get()
            if not p or not a or not pw:
                messagebox.showwarning("提示", "所有字段都不能为空", parent=dialog)
                return
            self.manager.add_account(p, a, pw)
            dialog.destroy()
            self._refresh_list()

        ttk.Button(card, text="保存", command=save, style="Primary.TButton").grid(row=3, column=1, sticky="e")
        plat.focus_set()
        dialog.bind("<Return>", lambda e: save())

    def close(self):
        self.manager.close()
        self.root.destroy()


if __name__ == "__main__":
    app = PasswordApp()
