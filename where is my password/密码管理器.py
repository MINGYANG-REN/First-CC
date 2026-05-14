"""
本地密码管理器 — 用主密码保护你的账号密码
数据加密存储在本地，不上传网络
"""
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
import base64
import os
import secrets
import sv_ttk
from cryptography.fernet import Fernet
import sys

# ========== 配色方案 ==========
COLORS = {
    "primary": "#4F46E5",      # 靛蓝 — 主按钮、强调
    "primary_hover": "#4338CA",
    "surface": "#F1F5F9",      # 页面背景
    "card": "#FFFFFF",         # 卡片白色
    "text": "#1E293B",         # 主文字
    "text_secondary": "#64748B",
    "danger": "#EF4444",       # 删除按钮
    "success": "#10B981",      # 成功提示
    "border": "#E2E8F0",
}
FONT = ("Microsoft YaHei", 10)
FONT_TITLE = ("Microsoft YaHei", 16, "bold")
FONT_MONO = ("Consolas", 11)

# ========== 数据库和加密核心 ==========
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "passwords.db")


def _derive_key(master_password: str, salt: bytes) -> bytes:
    digest = hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), salt, 600_000)
    return base64.urlsafe_b64encode(digest)


class PasswordManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_tables()
        self._fernet = None

    def _init_tables(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS master (
                id INTEGER PRIMARY KEY CHECK (id=1),
                password_hash TEXT NOT NULL,
                salt BLOB NOT NULL
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                account TEXT NOT NULL,
                encrypted_password BLOB NOT NULL
            )
        """)
        self.conn.commit()

    def is_first_time(self) -> bool:
        row = self.conn.execute("SELECT 1 FROM master WHERE id=1").fetchone()
        return row is None

    def set_master_password(self, master_password: str):
        salt = secrets.token_bytes(32)
        hash_val = hashlib.sha256(master_password.encode("utf-8") + salt).hexdigest()
        self.conn.execute("INSERT INTO master(id, password_hash, salt) VALUES(1,?,?)", (hash_val, salt))
        self.conn.commit()
        self._unlock(master_password)

    def verify_master_password(self, master_password: str) -> bool:
        row = self.conn.execute("SELECT password_hash, salt FROM master WHERE id=1").fetchone()
        if row is None:
            return False
        stored_hash, salt = row
        computed = hashlib.sha256(master_password.encode("utf-8") + salt).hexdigest()
        return computed == stored_hash

    def _unlock(self, master_password: str):
        row = self.conn.execute("SELECT salt FROM master WHERE id=1").fetchone()
        key = _derive_key(master_password, row[0])
        self._fernet = Fernet(key)

    def unlock(self, master_password: str) -> bool:
        if self.verify_master_password(master_password):
            self._unlock(master_password)
            return True
        return False

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
        self.root.resizable(False, False)
        self.root.configure(bg=COLORS["surface"])

        # 设置程序图标
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)

        # 应用 Sun Valley 现代主题
        sv_ttk.set_theme("light")

        # 自定义 ttk 样式
        style = ttk.Style()
        style.configure("Title.TLabel", font=FONT_TITLE, foreground=COLORS["primary"], background=COLORS["card"])
        style.configure("Subtitle.TLabel", font=FONT, foreground=COLORS["text_secondary"], background=COLORS["card"])
        style.configure("Card.TFrame", background=COLORS["card"])
        style.configure("Surface.TFrame", background=COLORS["surface"])

        # 主按钮风格
        style.configure("Primary.TButton", font=FONT)
        style.map("Primary.TButton",
                  background=[("active", COLORS["primary_hover"]), ("!active", COLORS["primary"])])

        # 危险按钮风格
        style.configure("Danger.TButton", font=FONT)

        # 居中显示
        w, h = 500, 440
        x = (self.root.winfo_screenwidth() - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

        if self.manager.is_first_time():
            self._show_setup()
        else:
            self._show_login()

        self.root.mainloop()

    # ========== 密码输入行 ==========
    @staticmethod
    def _make_pwd_row(parent, label_text):
        row = ttk.Frame(parent)
        ttk.Label(row, text=label_text, font=FONT).pack(side="left")
        entry = ttk.Entry(row, show="●", width=28, font=FONT_MONO)
        entry.pack(side="left", padx=(8, 4))

        def toggle():
            if entry.cget("show") == "●":
                entry.config(show="")
                btn.config(text="🙈")
            else:
                entry.config(show="●")
                btn.config(text="👁")

        btn = ttk.Button(row, text="👁", command=toggle, width=4)
        btn.pack(side="left")
        return row, entry

    # ========== 首次设置主密码 ==========
    def _show_setup(self):
        self._clear()
        self._title_bar("首次使用，设置主密码", "此密码用于加密所有数据，请牢记")

        card = ttk.Frame(self.root, padding=30, style="Card.TFrame")
        card.pack(padx=32, pady=(4, 24), fill="both")

        row1, self.pwd1 = self._make_pwd_row(card, "主密码")
        row1.pack(pady=(0, 14), anchor="w")
        row2, self.pwd2 = self._make_pwd_row(card, "确认密码")
        row2.pack(pady=(0, 24), anchor="w")

        btn = ttk.Button(card, text="设置主密码", command=self._do_setup, style="Primary.TButton")
        btn.pack()
        self.root.bind("<Return>", lambda e: self._do_setup())

    def _do_setup(self):
        pw1 = self.pwd1.get()
        pw2 = self.pwd2.get()
        if not pw1:
            messagebox.showwarning("提示", "密码不能为空")
            return
        if pw1 != pw2:
            messagebox.showwarning("提示", "两次输入不一致")
            return
        if len(pw1) < 4:
            messagebox.showwarning("提示", "主密码至少需要4位")
            return
        self.manager.set_master_password(pw1)
        self._show_main()

    # ========== 登录 ==========
    def _show_login(self):
        self._clear()
        self._title_bar("我的密码管理器", "输入主密码以解锁")

        card = ttk.Frame(self.root, padding=30, style="Card.TFrame")
        card.pack(padx=32, pady=(4, 24), fill="both")

        row, self.pwd_entry = self._make_pwd_row(card, "主密码")
        row.pack(pady=(0, 12))
        self.pwd_entry.focus_set()

        self.error_label = ttk.Label(card, text="", foreground=COLORS["danger"], font=FONT)
        self.error_label.pack(pady=(0, 16))

        btn = ttk.Button(card, text="解锁", command=self._do_login, style="Primary.TButton")
        btn.pack()
        self.root.bind("<Return>", lambda e: self._do_login())

    def _do_login(self):
        pw = self.pwd_entry.get()
        if not pw:
            return
        if self.manager.unlock(pw):
            self._show_main()
        else:
            self.error_label.config(text="密码错误，请重试")
            self.pwd_entry.delete(0, "end")

    # ========== 主界面 ==========
    def _show_main(self):
        self._clear()
        self.root.resizable(True, True)
        self.root.geometry("640x530")

        # 顶部导航栏
        nav = ttk.Frame(self.root, padding=(20, 14), style="Card.TFrame")
        nav.pack(fill="x", padx=0, pady=0)

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

        # placeholder 行为
        def on_focus_in(e):
            if search_entry.get() == "":
                search_entry.insert(0, "")

        def on_search(*_):
            self._refresh_list(self.search_var.get())

        self.search_var.trace_add("write", on_search)

        # 列表
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

        # 详情区 — 密码显示 + 操作
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

        copy_btn = ttk.Button(detail, text="📋 复制", command=self._copy_pwd)
        copy_btn.pack(side="left", padx=(0, 24))

        del_btn = ttk.Button(detail, text="🗑 删除", command=self._delete_selected, style="Danger.TButton")
        del_btn.pack(side="right")

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda e: self._copy_pwd())

        # 底部安全提示
        footer = ttk.Frame(self.root, padding=(20, 0, 20, 10))
        footer.pack(fill="x")
        ttk.Label(footer, text="数据加密存储在本地，无网络传输",
                  font=("Microsoft YaHei", 8), foreground=COLORS["text_secondary"]).pack(side="right")

        self._refresh_list()

    def _title_bar(self, title, subtitle):
        """统一的标题栏"""
        header = ttk.Frame(self.root, padding=(32, 28, 32, 18))
        header.pack(fill="x")
        ttk.Label(header, text=title, font=FONT_TITLE, foreground=COLORS["primary"]).pack()
        ttk.Label(header, text=subtitle, font=FONT, foreground=COLORS["text_secondary"]).pack(pady=(2, 0))

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

    def _clear(self):
        for w in self.root.winfo_children():
            w.destroy()
        self.root.resizable(False, False)
        w, h = 500, 440
        x = (self.root.winfo_screenwidth() - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def close(self):
        self.manager.close()
        self.root.destroy()


if __name__ == "__main__":
    app = PasswordApp()
