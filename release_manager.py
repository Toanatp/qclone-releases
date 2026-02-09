#!/usr/bin/env python3
"""
QClone Studio Release Manager - GUI tool Ä‘á»ƒ quáº£n lÃ½ release updates.
Dark Mode Professional UI

Cháº¡y script nÃ y trong thÆ° má»¥c qclone-releases:
    python release_manager.py
"""

import hashlib
import json
import os
import re
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Constants - QClone Studio specific
APP_NAME = "QClone Studio"
APP_SHORT_NAME = "qclone"
DEFAULT_UPDATE_FOLDER = "qclone_file_update"
DEFAULT_AVU_NAME = "qclone_update.ssu"  # QClone Update format
DEFAULT_APPCAST = "appcast.xml"

# ÄÆ°á»ng dáº«n tuyá»‡t Ä‘á»‘i Ä‘áº¿n thÆ° má»¥c chá»©a script nÃ y
SCRIPT_DIR = Path(__file__).resolve().parent

# Private key paths - Æ°u tiÃªn file trong cÃ¹ng thÆ° má»¥c vá»›i script
PRIVATE_KEY_FILENAME = "update_private_key.pem"
LOCAL_PRIVATE_KEY_PATH = SCRIPT_DIR / PRIVATE_KEY_FILENAME  # Æ¯u tiÃªn 1: cÃ¹ng thÆ° má»¥c vá»›i script
FALLBACK_PRIVATE_KEY_PATH = SCRIPT_DIR.parent / "tools" / PRIVATE_KEY_FILENAME  # Æ¯u tiÃªn 2: ../tools/

# GitHub Repository - Thay Ä‘á»•i theo repo cá»§a báº¡n
GITHUB_REPO = "Toanatp/qclone-releases"
GITHUB_BASE_URL = f"https://github.com/{GITHUB_REPO}"

# Dark Theme Colors
COLORS = {
    "bg_dark": "#161B22",
    "bg_medium": "#1D2430",
    "bg_light": "#30363D",
    "bg_input": "#21262D",
    "fg_primary": "#E0E6F1",
    "fg_secondary": "#8B949E",
    "fg_muted": "#6E7681",
    "accent": "#08D9D6",
    "accent_hover": "#22e0da",
    "success": "#22C55E",
    "warning": "#F59E0B",
    "error": "#EF4444",
    "border": "#30363D",
}


def setup_dark_theme(root):
    """Cáº¥u hÃ¬nh dark theme cho ttk widgets."""
    style = ttk.Style()
    
    # Configure main theme
    style.theme_use('clam')
    
    # Frame styles
    style.configure("TFrame", background=COLORS["bg_dark"])
    style.configure("Card.TFrame", background=COLORS["bg_medium"])
    
    # Label styles
    style.configure("TLabel", background=COLORS["bg_dark"], foreground=COLORS["fg_primary"], font=("Segoe UI", 10))
    style.configure("Title.TLabel", font=("Segoe UI", 11, "bold"), foreground=COLORS["fg_primary"])
    style.configure("Muted.TLabel", foreground=COLORS["fg_muted"])
    style.configure("Warning.TLabel", foreground=COLORS["warning"], font=("Segoe UI", 10, "bold"))
    style.configure("Card.TLabel", background=COLORS["bg_medium"])
    
    # Entry styles
    style.configure("TEntry", fieldbackground=COLORS["bg_input"], foreground=COLORS["fg_primary"],
                   insertcolor=COLORS["fg_primary"], borderwidth=1)
    style.map("TEntry", fieldbackground=[("focus", COLORS["bg_light"])])
    
    # Button styles
    style.configure("TButton", background=COLORS["bg_light"], foreground=COLORS["fg_primary"],
                   font=("Segoe UI", 10), padding=(15, 8), borderwidth=0)
    style.map("TButton", background=[("active", COLORS["accent"]), ("pressed", COLORS["accent_hover"])])
    
    style.configure("Accent.TButton", background=COLORS["accent"], foreground=COLORS["bg_dark"], font=("Segoe UI", 10, "bold"))
    style.map("Accent.TButton", background=[("active", COLORS["accent_hover"])])
    
    style.configure("Success.TButton", background=COLORS["success"], foreground=COLORS["bg_dark"])
    style.configure("Warning.TButton", background=COLORS["warning"], foreground=COLORS["bg_dark"])
    
    # LabelFrame styles
    style.configure("TLabelframe", background=COLORS["bg_medium"], borderwidth=1, relief="flat")
    style.configure("TLabelframe.Label", background=COLORS["bg_medium"], foreground=COLORS["accent"],
                   font=("Segoe UI", 10, "bold"))
    
    # Treeview styles
    style.configure("Treeview", background=COLORS["bg_input"], foreground=COLORS["fg_primary"],
                   fieldbackground=COLORS["bg_input"], borderwidth=0, font=("Consolas", 9))
    style.configure("Treeview.Heading", background=COLORS["bg_light"], foreground=COLORS["fg_primary"],
                   font=("Segoe UI", 9, "bold"))
    style.map("Treeview", background=[("selected", COLORS["accent"])])
    
    # Scrollbar
    style.configure("TScrollbar", background=COLORS["bg_light"], troughcolor=COLORS["bg_dark"])
    
    # Combobox
    style.configure("TCombobox", fieldbackground=COLORS["bg_input"], background=COLORS["bg_light"],
                   foreground=COLORS["fg_primary"])
    
    # Separator
    style.configure("TSeparator", background=COLORS["border"])
    
    root.configure(bg=COLORS["bg_dark"])


def compute_sha256(file_path: Path) -> str:
    """TÃ­nh SHA256 hash cá»§a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest().upper()


def sign_file_with_nacl(file_path: Path, private_key_path: Path) -> Optional[str]:
    """KÃ½ file vá»›i Ed25519 private key sá»­ dá»¥ng PyNaCl."""
    try:
        from nacl.signing import SigningKey
        import base64
    except ImportError:
        return None
    
    pem_content = private_key_path.read_text()
    lines = pem_content.strip().split('\n')
    key_lines = [l for l in lines if not l.startswith('-----')]
    key_b64 = ''.join(key_lines)
    key_bytes = base64.b64decode(key_b64)
    
    if len(key_bytes) == 64:
        seed = key_bytes[:32]
    elif len(key_bytes) == 32:
        seed = key_bytes
    else:
        seed = key_bytes[-32:]
    
    signing_key = SigningKey(seed)
    file_data = file_path.read_bytes()
    signed = signing_key.sign(file_data)
    return base64.b64encode(signed.signature).decode('ascii')


def create_avu_package(source_folder: Path, output_path: Path) -> bool:
    """Táº¡o file .ssu (QClone Update) tá»« thÆ° má»¥c source."""
    try:
        manifest_path = source_folder / "manifest.json"
        files_folder = source_folder / "files"
        
        if not manifest_path.exists():
            raise FileNotFoundError("manifest.json khÃ´ng tá»“n táº¡i")
        
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.write(manifest_path, "manifest.json")
            if files_folder.exists():
                for file_path in files_folder.rglob("*"):
                    if file_path.is_file():
                        arcname = file_path.relative_to(source_folder)
                        zf.write(file_path, arcname)
        return True
    except Exception as e:
        print(f"Lá»—i táº¡o .ssu: {e}")
        return False


def git_commit_and_push(work_dir: Path, version: str, files_to_commit: list) -> tuple[bool, str]:
    """Commit vÃ  push changes lÃªn Git."""
    try:
        result = subprocess.run(['git', 'status'], capture_output=True, text=True, cwd=work_dir)
        if result.returncode != 0:
            return False, "KhÃ´ng pháº£i git repository"
        
        for file in files_to_commit:
            subprocess.run(['git', 'add', str(file)], capture_output=True, text=True, cwd=work_dir)
        
        commit_msg = f"Release {APP_NAME} version {version}"
        result = subprocess.run(['git', 'commit', '-m', commit_msg], capture_output=True, text=True, cwd=work_dir)
        if result.returncode != 0 and "nothing to commit" not in result.stdout:
            return False, f"Lá»—i commit: {result.stderr}"
        
        result = subprocess.run(['git', 'push'], capture_output=True, text=True, cwd=work_dir)
        if result.returncode != 0:
            return False, f"Lá»—i push: {result.stderr}"
        
        return True, f"ÄÃ£ push thÃ nh cÃ´ng! Commit: {commit_msg}"
    except Exception as e:
        return False, str(e)


def update_appcast_xml(appcast_path: Path, version: str, download_url: str, sha256: str, 
                       signature: str, file_size: int, release_notes_url: str, title: str,
                       build_number: str = "") -> bool:
    """Cáº­p nháº­t file appcast.xml vá»›i thÃ´ng tin release má»›i."""
    try:
        content = appcast_path.read_text(encoding='utf-8')
        
        # Update URL - support ssu/avu/vwu/zip from GUI value
        content = re.sub(r'url="[^"]*\.(?:ssu|avu|vwu|zip)"', f'url="{download_url}"', content)
        content = re.sub(r'sparkle:version="[^"]*"', f'sparkle:version="{version}"', content)
        content = re.sub(r'sparkle:shortVersionString="[^"]*"', f'sparkle:shortVersionString="{version}"', content)
        content = re.sub(r'sparkle:sha256="[^"]*"', f'sparkle:sha256="{sha256}"', content)
        content = re.sub(r'sparkle:edSignature="[^"]*"', f'sparkle:edSignature="{signature}"', content)
        content = re.sub(r'length="[^"]*"', f'length="{file_size}"', content)
        
        if build_number:
            content = re.sub(r'sparkle:osBuild="[^"]*"', f'sparkle:osBuild="{build_number}"', content)
        
        content = re.sub(r'<sparkle:releaseNotesLink>[^<]*</sparkle:releaseNotesLink>',
                        f'<sparkle:releaseNotesLink>{release_notes_url}</sparkle:releaseNotesLink>', content)
        content = re.sub(r'(<item>\s*<title>)[^<]*(</title>)', f'\\g<1>{title}\\g<2>', content)
        
        pub_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        content = re.sub(r'<pubDate>[^<]*</pubDate>', f'<pubDate>{pub_date}</pubDate>', content)
        
        appcast_path.write_text(content, encoding='utf-8')
        return True
    except Exception as e:
        print(f"Lá»—i: {e}")
        return False


class ManifestEditorDialog:
    """Dialog Ä‘á»ƒ chá»‰nh sá»­a manifest.json."""
    
    def __init__(self, parent, manifest_path: Path, version: str = ""):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"{APP_NAME} - Manifest Editor")
        self.dialog.geometry("900x550")
        self.dialog.configure(bg=COLORS["bg_dark"])
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.manifest_path = manifest_path
        self.files_data = []
        self.version_var = tk.StringVar(value=version)
        
        setup_dark_theme(self.dialog)
        self._create_ui()
        self._load_manifest()
    
    def _create_ui(self):
        main = ttk.Frame(self.dialog, padding=15)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header = ttk.Frame(main)
        header.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(header, text="ðŸ“„ Manifest Editor", style="Title.TLabel").pack(side=tk.LEFT)
        
        # Version row
        ver_frame = ttk.Frame(main)
        ver_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(ver_frame, text="Version:").pack(side=tk.LEFT)
        ver_entry = tk.Entry(ver_frame, textvariable=self.version_var, width=15, 
                            bg=COLORS["bg_input"], fg=COLORS["fg_primary"], 
                            insertbackground=COLORS["fg_primary"], relief="flat", font=("Consolas", 11))
        ver_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # Content area
        content = ttk.Frame(main)
        content.pack(fill=tk.BOTH, expand=True)
        
        # Treeview
        tree_frame = ttk.Frame(content)
        tree_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        columns = ("source", "target", "type", "hash")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=12)
        self.tree.heading("source", text="Source")
        self.tree.heading("target", text="Target")
        self.tree.heading("type", text="Type")
        self.tree.heading("hash", text="Hash")
        self.tree.column("source", width=220)
        self.tree.column("target", width=180)
        self.tree.column("type", width=70)
        self.tree.column("hash", width=180)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons panel
        btn_panel = ttk.Frame(content, padding=(15, 0, 0, 0))
        btn_panel.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(btn_panel, text="âž• ThÃªm File", command=self._add_file, width=16).pack(pady=3, fill=tk.X)
        ttk.Button(btn_panel, text="ðŸ“ ThÃªm ThÆ° má»¥c", command=self._add_directory, width=16).pack(pady=3, fill=tk.X)
        ttk.Separator(btn_panel, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=12)
        ttk.Button(btn_panel, text="âœï¸ Sá»­a", command=self._edit_selected, width=16).pack(pady=3, fill=tk.X)
        ttk.Button(btn_panel, text="ðŸ—‘ï¸ XÃ³a", command=self._delete_selected, width=16).pack(pady=3, fill=tk.X)
        ttk.Button(btn_panel, text="ðŸ”„ TÃ­nh Hash", command=self._recalculate_hash, width=16).pack(pady=3, fill=tk.X)
        ttk.Separator(btn_panel, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=12)
        ttk.Button(btn_panel, text="ðŸ’¾ LÆ°u", command=self._save_manifest, style="Accent.TButton", width=16).pack(pady=3, fill=tk.X)
        ttk.Button(btn_panel, text="âŒ ÄÃ³ng", command=self.dialog.destroy, width=16).pack(pady=3, fill=tk.X)

    def _load_manifest(self):
        if not self.manifest_path.exists():
            return
        try:
            with open(self.manifest_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.version_var.set(data.get("version", ""))
            self.files_data = data.get("files", [])
            self._refresh_tree()
        except Exception as e:
            messagebox.showerror("Lá»—i", f"KhÃ´ng thá»ƒ Ä‘á»c manifest:\n{e}")
    
    def _refresh_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for f in self.files_data:
            h = f.get("hash", "")[:35] + "..." if len(f.get("hash", "")) > 35 else f.get("hash", "")
            self.tree.insert("", tk.END, values=(f.get("source", ""), f.get("target", ""), f.get("type", "file"), h))
    
    def _add_file(self):
        dialog = FileEntryDialog(self.dialog, self.manifest_path.parent, "file")
        if dialog.result:
            self.files_data.append(dialog.result)
            self._refresh_tree()
    
    def _add_directory(self):
        dialog = FileEntryDialog(self.dialog, self.manifest_path.parent, "directory")
        if dialog.result:
            self.files_data.append(dialog.result)
            self._refresh_tree()
    
    def _edit_selected(self):
        selected = self.tree.selection()
        if not selected:
            return
        idx = self.tree.index(selected[0])
        dialog = FileEntryDialog(self.dialog, self.manifest_path.parent, 
                                self.files_data[idx].get("type", "file"), self.files_data[idx])
        if dialog.result:
            self.files_data[idx] = dialog.result
            self._refresh_tree()
    
    def _delete_selected(self):
        selected = self.tree.selection()
        if selected and messagebox.askyesno("XÃ¡c nháº­n", "XÃ³a item nÃ y?"):
            del self.files_data[self.tree.index(selected[0])]
            self._refresh_tree()
    
    def _recalculate_hash(self):
        selected = self.tree.selection()
        if not selected:
            return
        idx = self.tree.index(selected[0])
        if self.files_data[idx].get("type") == "directory":
            return
        source_path = self.manifest_path.parent / self.files_data[idx].get("source", "")
        if source_path.exists():
            self.files_data[idx]["hash"] = "sha256:" + compute_sha256(source_path)
            self._refresh_tree()
            messagebox.showinfo("OK", "ÄÃ£ tÃ­nh hash!")
    
    def _save_manifest(self):
        data = {
            "version": self.version_var.get().strip(),
            "app_name": APP_NAME,
            "files": self.files_data,
            "remove": [],
            "post_install": {
                "restart_required": True,
                "message": f"{APP_NAME} Ä‘Ã£ Ä‘Æ°á»£c cáº­p nháº­t thÃ nh cÃ´ng!"
            }
        }
        try:
            with open(self.manifest_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            messagebox.showinfo("OK", "ÄÃ£ lÆ°u manifest.json!")
            self.dialog.destroy()
        except Exception as e:
            messagebox.showerror("Lá»—i", str(e))


class FileEntryDialog:
    """Dialog Ä‘á»ƒ thÃªm/sá»­a file entry trong manifest."""
    
    def __init__(self, parent, base_path: Path, file_type: str = "file", existing: dict = None):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("File Entry")
        self.dialog.geometry("550x280")
        self.dialog.configure(bg=COLORS["bg_dark"])
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.base_path = base_path
        self.result = None
        
        self.source_var = tk.StringVar(value=existing.get("source", "") if existing else "")
        self.target_var = tk.StringVar(value=existing.get("target", "") if existing else "")
        self.type_var = tk.StringVar(value=existing.get("type", file_type) if existing else file_type)
        self.hash_var = tk.StringVar(value=existing.get("hash", "") if existing else "")
        
        setup_dark_theme(self.dialog)
        self._create_ui()
        self.dialog.wait_window()
    
    def _create_ui(self):
        main = ttk.Frame(self.dialog, padding=20)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Source
        ttk.Label(main, text="Source:").grid(row=0, column=0, sticky=tk.W, pady=8)
        src_frame = ttk.Frame(main)
        src_frame.grid(row=0, column=1, sticky=tk.EW, pady=8)
        tk.Entry(src_frame, textvariable=self.source_var, width=45, bg=COLORS["bg_input"], 
                fg=COLORS["fg_primary"], insertbackground=COLORS["fg_primary"], relief="flat").pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(src_frame, text="ðŸ“", command=self._browse, width=3).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Target
        ttk.Label(main, text="Target:").grid(row=1, column=0, sticky=tk.W, pady=8)
        tk.Entry(main, textvariable=self.target_var, width=50, bg=COLORS["bg_input"],
                fg=COLORS["fg_primary"], insertbackground=COLORS["fg_primary"], relief="flat").grid(row=1, column=1, sticky=tk.EW, pady=8)
        
        # Type
        ttk.Label(main, text="Type:").grid(row=2, column=0, sticky=tk.W, pady=8)
        ttk.Combobox(main, textvariable=self.type_var, values=["file", "directory"], width=15).grid(row=2, column=1, sticky=tk.W, pady=8)
        
        # Hash
        ttk.Label(main, text="Hash:").grid(row=3, column=0, sticky=tk.W, pady=8)
        hash_frame = ttk.Frame(main)
        hash_frame.grid(row=3, column=1, sticky=tk.EW, pady=8)
        tk.Entry(hash_frame, textvariable=self.hash_var, width=45, bg=COLORS["bg_input"],
                fg=COLORS["fg_primary"], insertbackground=COLORS["fg_primary"], relief="flat").pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(hash_frame, text="ðŸ”„", command=self._calc_hash, width=3).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Buttons
        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=20)
        ttk.Button(btn_frame, text="âœ… OK", command=self._save, style="Accent.TButton", width=12).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="âŒ Há»§y", command=self.dialog.destroy, width=12).pack(side=tk.LEFT, padx=10)
        
        main.columnconfigure(1, weight=1)
    
    def _browse(self):
        if self.type_var.get() == "directory":
            path = filedialog.askdirectory(initialdir=self.base_path / "files")
        else:
            path = filedialog.askopenfilename(initialdir=self.base_path / "files")
        if path:
            try:
                rel = Path(path).relative_to(self.base_path)
                self.source_var.set(str(rel).replace("\\", "/"))
                if not self.target_var.get():
                    self.target_var.set(str(rel).replace("files/", "").replace("\\", "/"))
            except:
                self.source_var.set(path)
    
    def _calc_hash(self):
        if self.type_var.get() == "directory":
            return
        source = self.source_var.get()
        if source:
            file_path = self.base_path / source
            if file_path.exists():
                self.hash_var.set("sha256:" + compute_sha256(file_path))
    
    def _save(self):
        if not self.source_var.get() or not self.target_var.get():
            messagebox.showwarning("Cáº£nh bÃ¡o", "Nháº­p Ä‘áº§y Ä‘á»§ Source vÃ  Target")
            return
        self.result = {"source": self.source_var.get(), "target": self.target_var.get(), "type": self.type_var.get()}
        if self.type_var.get() == "file" and self.hash_var.get():
            self.result["hash"] = self.hash_var.get()
        self.dialog.destroy()


class ReleaseManagerApp:
    """Main application class cho QClone Studio Release Manager."""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} Release Manager")
        self.root.geometry("850x800")
        self.root.configure(bg=COLORS["bg_dark"])
        self.root.resizable(True, True)
        
        # Variables
        self.version_var = tk.StringVar(value="2.0.0")
        self.build_number_var = tk.StringVar(value="20000")
        self.title_var = tk.StringVar(value=f"{APP_NAME} 2.0.0")
        self.sha256_var = tk.StringVar()
        self.signature_var = tk.StringVar()
        self.file_size_var = tk.StringVar()
        self.download_url_var = tk.StringVar()
        self.release_notes_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        
        # Paths
        self.work_dir = Path.cwd()
        self.update_folder = self.work_dir / DEFAULT_UPDATE_FOLDER
        self.avu_path = self.update_folder / DEFAULT_AVU_NAME
        self.appcast_path = self.work_dir / DEFAULT_APPCAST
        self.manifest_path = self.update_folder / "manifest.json"
        self.private_key_path = None
        
        # Try to find private key - Æ°u tiÃªn file trong cÃ¹ng thÆ° má»¥c vá»›i script
        possible_key_paths = [
            LOCAL_PRIVATE_KEY_PATH,      # Æ¯u tiÃªn 1: cÃ¹ng thÆ° má»¥c vá»›i script
            FALLBACK_PRIVATE_KEY_PATH,   # Æ¯u tiÃªn 2: ../tools/update_private_key.pem
            self.work_dir / "tools" / PRIVATE_KEY_FILENAME,  # Æ¯u tiÃªn 3: working dir
        ]
        for key_path in possible_key_paths:
            if key_path.exists():
                self.private_key_path = key_path
                break
        
        setup_dark_theme(root)
        self._create_ui()
        self._load_current_values()
        self._load_version_json()
    
    def _load_version_json(self):
        """Load version tá»« version.json náº¿u cÃ³."""
        version_json = self.work_dir / "version.json"
        if not version_json.exists():
            version_json = self.work_dir.parent / "version.json"
        
        if version_json.exists():
            try:
                with open(version_json, 'r') as f:
                    data = json.load(f)
                if "version" in data:
                    self.version_var.set(data["version"])
                    self.title_var.set(f"{APP_NAME} {data['version']}")
                if "build_number" in data:
                    self.build_number_var.set(str(data["build_number"]))
                self._auto_fill_urls()
            except Exception:
                pass
    
    def _create_entry(self, parent, textvariable, width=50):
        """Create styled entry."""
        entry = tk.Entry(parent, textvariable=textvariable, width=width,
                        bg=COLORS["bg_input"], fg=COLORS["fg_primary"],
                        insertbackground=COLORS["fg_primary"], relief="flat",
                        font=("Consolas", 10), highlightthickness=1,
                        highlightbackground=COLORS["border"], highlightcolor=COLORS["accent"])
        return entry
    
    def _create_ui(self):
        # Main container with scrollbar
        canvas = tk.Canvas(self.root, bg=COLORS["bg_dark"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        main_frame = ttk.Frame(canvas, padding=20)
        
        main_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=main_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Enable mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Header
        header = ttk.Frame(main_frame)
        header.pack(fill=tk.X, pady=(0, 20))
        ttk.Label(header, text=f"ðŸŽ™ï¸ {APP_NAME} Release Manager", font=("Segoe UI", 16, "bold")).pack(side=tk.LEFT)
        
        # === Section 1: Version Info ===
        self._create_section(main_frame, "ðŸ“‹ ThÃ´ng tin phiÃªn báº£n", self._create_version_section)
        
        # === Section 2: Manifest ===
        self._create_section(main_frame, "ðŸ“„ Manifest.json", self._create_manifest_section)
        
        # === Section 3: Package ===
        self._create_section(main_frame, "ðŸ“¦ ÄÃ³ng gÃ³i", self._create_package_section)
        
        # === Section 4: Security ===
        self._create_section(main_frame, "ðŸ” SHA256 & Chá»¯ kÃ½", self._create_security_section)
        
        # === Section 5: Appcast ===
        self._create_section(main_frame, "ðŸ“ Appcast.xml", self._create_appcast_section)
        
        # === Section 6: Git ===
        self._create_section(main_frame, "ðŸš€ Git & Deploy", self._create_git_section)
        
        # Warning
        warn_frame = ttk.Frame(main_frame)
        warn_frame.pack(fill=tk.X, pady=15)
        tk.Label(warn_frame, text="âš ï¸ Nhá»› upload file .ssu lÃªn GitHub Releases trÆ°á»›c khi test update!",
                bg=COLORS["bg_dark"], fg=COLORS["warning"], font=("Segoe UI", 11, "bold")).pack()
        
        # Status bar
        status_frame = tk.Frame(main_frame, bg=COLORS["bg_light"], height=35)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        status_frame.pack_propagate(False)
        tk.Label(status_frame, textvariable=self.status_var, bg=COLORS["bg_light"], 
                fg=COLORS["fg_secondary"], font=("Segoe UI", 9), anchor="w", padx=10).pack(fill=tk.BOTH, expand=True)

    def _create_section(self, parent, title, content_func):
        """Create a styled section card."""
        card = tk.Frame(parent, bg=COLORS["bg_medium"], highlightbackground=COLORS["border"], 
                       highlightthickness=1, padx=15, pady=12)
        card.pack(fill=tk.X, pady=8)
        
        # Title
        tk.Label(card, text=title, bg=COLORS["bg_medium"], fg=COLORS["accent"],
                font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Content
        content_func(card)
    
    def _create_version_section(self, parent):
        grid = tk.Frame(parent, bg=COLORS["bg_medium"])
        grid.pack(fill=tk.X)
        
        # Row 1: Version, Build Number & Title
        row1 = tk.Frame(grid, bg=COLORS["bg_medium"])
        row1.pack(fill=tk.X, pady=3)
        tk.Label(row1, text="Version:", bg=COLORS["bg_medium"], fg=COLORS["fg_secondary"], width=12, anchor="w").pack(side=tk.LEFT)
        self._create_entry(row1, self.version_var, 12).pack(side=tk.LEFT)
        tk.Label(row1, text="Build:", bg=COLORS["bg_medium"], fg=COLORS["fg_secondary"], width=6, anchor="e").pack(side=tk.LEFT, padx=(10, 0))
        self._create_entry(row1, self.build_number_var, 8).pack(side=tk.LEFT, padx=(5, 0))
        tk.Label(row1, text="Title:", bg=COLORS["bg_medium"], fg=COLORS["fg_secondary"], width=6, anchor="e").pack(side=tk.LEFT, padx=(10, 0))
        self._create_entry(row1, self.title_var, 25).pack(side=tk.LEFT, padx=(5, 0))
        
        # Row 2: Download URL
        row2 = tk.Frame(grid, bg=COLORS["bg_medium"])
        row2.pack(fill=tk.X, pady=3)
        tk.Label(row2, text="Download URL:", bg=COLORS["bg_medium"], fg=COLORS["fg_secondary"], width=12, anchor="w").pack(side=tk.LEFT)
        self._create_entry(row2, self.download_url_var, 70).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Row 3: Release Notes
        row3 = tk.Frame(grid, bg=COLORS["bg_medium"])
        row3.pack(fill=tk.X, pady=3)
        tk.Label(row3, text="Release Notes:", bg=COLORS["bg_medium"], fg=COLORS["fg_secondary"], width=12, anchor="w").pack(side=tk.LEFT)
        self._create_entry(row3, self.release_notes_var, 70).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Button
        btn_row = tk.Frame(grid, bg=COLORS["bg_medium"])
        btn_row.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(btn_row, text="ðŸ”„ Auto-fill URLs", command=self._auto_fill_urls).pack(side=tk.LEFT)
    
    def _create_manifest_section(self, parent):
        btn_row = tk.Frame(parent, bg=COLORS["bg_medium"])
        btn_row.pack(fill=tk.X)
        ttk.Button(btn_row, text="ðŸ“ Chá»‰nh sá»­a Manifest", command=self._edit_manifest, width=20).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_row, text="ðŸ”„ Sync Version", command=self._sync_manifest_version).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_row, text="ðŸ“ Má»Ÿ thÆ° má»¥c", command=self._open_update_folder).pack(side=tk.LEFT)
    
    def _create_package_section(self, parent):
        btn_row = tk.Frame(parent, bg=COLORS["bg_medium"])
        btn_row.pack(fill=tk.X)
        ttk.Button(btn_row, text="ðŸ“¦ BÆ°á»›c 1: Táº¡o file .ssu", command=self._create_avu, style="Accent.TButton", width=25).pack(side=tk.LEFT)
    
    def _create_security_section(self, parent):
        grid = tk.Frame(parent, bg=COLORS["bg_medium"])
        grid.pack(fill=tk.X)
        
        # SHA256
        row1 = tk.Frame(grid, bg=COLORS["bg_medium"])
        row1.pack(fill=tk.X, pady=3)
        tk.Label(row1, text="SHA256:", bg=COLORS["bg_medium"], fg=COLORS["fg_secondary"], width=10, anchor="w").pack(side=tk.LEFT)
        self._create_entry(row1, self.sha256_var, 70).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # File size
        row2 = tk.Frame(grid, bg=COLORS["bg_medium"])
        row2.pack(fill=tk.X, pady=3)
        tk.Label(row2, text="File size:", bg=COLORS["bg_medium"], fg=COLORS["fg_secondary"], width=10, anchor="w").pack(side=tk.LEFT)
        self._create_entry(row2, self.file_size_var, 20).pack(side=tk.LEFT)
        
        # Signature
        row3 = tk.Frame(grid, bg=COLORS["bg_medium"])
        row3.pack(fill=tk.X, pady=3)
        tk.Label(row3, text="Signature:", bg=COLORS["bg_medium"], fg=COLORS["fg_secondary"], width=10, anchor="w").pack(side=tk.LEFT)
        self._create_entry(row3, self.signature_var, 70).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Buttons
        btn_row = tk.Frame(grid, bg=COLORS["bg_medium"])
        btn_row.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(btn_row, text="ðŸ”¢ BÆ°á»›c 2: TÃ­nh SHA256", command=self._calculate_sha256, width=22).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_row, text="ðŸ”‘ Chá»n Private Key", command=self._select_private_key).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_row, text="âœï¸ BÆ°á»›c 3: KÃ½ file", command=self._sign_file, style="Accent.TButton", width=18).pack(side=tk.LEFT)
    
    def _create_appcast_section(self, parent):
        btn_row = tk.Frame(parent, bg=COLORS["bg_medium"])
        btn_row.pack(fill=tk.X)
        ttk.Button(btn_row, text="ðŸ’¾ BÆ°á»›c 4: Cáº­p nháº­t appcast.xml", command=self._update_appcast, style="Accent.TButton", width=28).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_row, text="ðŸ“„ Má»Ÿ appcast.xml", command=self._open_appcast).pack(side=tk.LEFT)
    
    def _create_git_section(self, parent):
        btn_row = tk.Frame(parent, bg=COLORS["bg_medium"])
        btn_row.pack(fill=tk.X)
        ttk.Button(btn_row, text="ðŸš€ BÆ°á»›c 5: Commit & Push", command=self._git_commit_push, style="Accent.TButton", width=22).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_row, text="ðŸ“‹ Git Status", command=self._git_status).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_row, text="ðŸŒ GitHub Releases", command=self._open_github_releases).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_row, text="ðŸ“‚ Má»Ÿ file .ssu", command=self._open_avu_location).pack(side=tk.LEFT)

    def _set_status(self, msg):
        self.status_var.set(msg)
        self.root.update()
    
    def _load_current_values(self):
        if not self.appcast_path.exists():
            self._set_status("âš ï¸ appcast.xml khÃ´ng tá»“n táº¡i")
            return
        try:
            content = self.appcast_path.read_text(encoding='utf-8')
            for pattern, var in [
                (r'sparkle:version="([^"]*)"', self.version_var),
                (r'<item>\s*<title>([^<]*)</title>', self.title_var),
                (r'url="([^"]*)"', self.download_url_var),
                (r'<sparkle:releaseNotesLink>([^<]*)</sparkle:releaseNotesLink>', self.release_notes_var),
                (r'sparkle:sha256="([^"]*)"', self.sha256_var),
                (r'sparkle:edSignature="([^"]*)"', self.signature_var),
                (r'length="([^"]*)"', self.file_size_var),
                (r'sparkle:osBuild="([^"]*)"', self.build_number_var),
            ]:
                match = re.search(pattern, content)
                if match:
                    var.set(match.group(1))
            self._set_status("âœ… ÄÃ£ load tá»« appcast.xml")
        except Exception as e:
            self._set_status(f"âŒ Lá»—i: {e}")
    
    def _auto_fill_urls(self):
        version = self.version_var.get().strip()
        if not version:
            messagebox.showwarning("Cáº£nh bÃ¡o", "Nháº­p version trÆ°á»›c")
            return
        self.download_url_var.set(f"{GITHUB_BASE_URL}/releases/download/{version}/{DEFAULT_AVU_NAME}")
        self.release_notes_var.set(f"{GITHUB_BASE_URL}/releases/tag/{version}")
        self.title_var.set(f"{APP_NAME} {version}")
        self._set_status(f"âœ… Auto-fill URLs cho v{version}")
    
    def _edit_manifest(self):
        if not self.manifest_path.exists():
            if messagebox.askyesno("Táº¡o má»›i", "Táº¡o manifest.json má»›i?"):
                self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
                data = {
                    "version": self.version_var.get(),
                    "app_name": APP_NAME,
                    "files": [],
                    "remove": [],
                    "post_install": {
                        "restart_required": True,
                        "message": f"{APP_NAME} Ä‘Ã£ Ä‘Æ°á»£c cáº­p nháº­t thÃ nh cÃ´ng!"
                    }
                }
                with open(self.manifest_path, 'w') as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
            else:
                return
        ManifestEditorDialog(self.root, self.manifest_path, self.version_var.get())
    
    def _sync_manifest_version(self):
        if not self.manifest_path.exists():
            return
        try:
            with open(self.manifest_path, 'r') as f:
                data = json.load(f)
            data["version"] = self.version_var.get().strip()
            data["app_name"] = APP_NAME
            with open(self.manifest_path, 'w') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            self._set_status(f"âœ… Sync version {data['version']}")
        except Exception as e:
            messagebox.showerror("Lá»—i", str(e))
    
    def _open_update_folder(self):
        if self.update_folder.exists():
            os.startfile(self.update_folder)
        else:
            messagebox.showwarning("Cáº£nh bÃ¡o", f"ThÆ° má»¥c {DEFAULT_UPDATE_FOLDER} khÃ´ng tá»“n táº¡i")
    
    def _open_appcast(self):
        if self.appcast_path.exists():
            os.startfile(self.appcast_path)
    
    def _open_avu_location(self):
        if self.avu_path.exists():
            subprocess.run(['explorer', '/select,', str(self.avu_path)])
        elif self.update_folder.exists():
            os.startfile(self.update_folder)
    
    def _open_github_releases(self):
        import webbrowser
        webbrowser.open(f"{GITHUB_BASE_URL}/releases/new")
    
    def _create_avu(self):
        if not self.update_folder.exists() or not self.manifest_path.exists():
            messagebox.showerror("Lá»—i", f"Thiáº¿u thÆ° má»¥c {DEFAULT_UPDATE_FOLDER} hoáº·c manifest.json")
            return
        if not messagebox.askyesno("XÃ¡c nháº­n", "ÄÃ£ cáº­p nháº­t files má»›i?\nTiáº¿p tá»¥c táº¡o .ssu?"):
            return
        self._set_status("â³ Äang táº¡o .ssu...")
        if create_avu_package(self.update_folder, self.avu_path):
            size = self.avu_path.stat().st_size
            self.file_size_var.set(str(size))
            self._set_status(f"âœ… ÄÃ£ táº¡o .ssu ({size:,} bytes)")
            messagebox.showinfo("OK", f"ÄÃ£ táº¡o {DEFAULT_AVU_NAME}!\nSize: {size:,} bytes")
        else:
            messagebox.showerror("Lá»—i", "KhÃ´ng thá»ƒ táº¡o .ssu")
    
    def _calculate_sha256(self):
        if not self.avu_path.exists():
            messagebox.showerror("Lá»—i", f"File {DEFAULT_AVU_NAME} khÃ´ng tá»“n táº¡i")
            return
        self._set_status("â³ Äang tÃ­nh SHA256...")
        sha = compute_sha256(self.avu_path)
        self.sha256_var.set(sha)
        self.file_size_var.set(str(self.avu_path.stat().st_size))
        self._set_status(f"âœ… SHA256: {sha[:20]}...")
    
    def _select_private_key(self):
        path = filedialog.askopenfilename(title="Chá»n Private Key", filetypes=[("PEM", "*.pem")])
        if path:
            self.private_key_path = Path(path)
            self._set_status(f"ðŸ”‘ Key: {self.private_key_path.name}")
    
    def _sign_file(self):
        if not self.avu_path.exists():
            messagebox.showerror("Lá»—i", f"File {DEFAULT_AVU_NAME} khÃ´ng tá»“n táº¡i")
            return
        if not self.private_key_path or not self.private_key_path.exists():
            self._select_private_key()
            if not self.private_key_path:
                return
        if not messagebox.askyesno("XÃ¡c nháº­n", f"KÃ½ file vá»›i {self.private_key_path.name}?"):
            return
        self._set_status("â³ Äang kÃ½...")
        sig = sign_file_with_nacl(self.avu_path, self.private_key_path)
        if sig:
            self.signature_var.set(sig)
            self._set_status("âœ… ÄÃ£ kÃ½ thÃ nh cÃ´ng")
        else:
            messagebox.showerror("Lá»—i", "KhÃ´ng thá»ƒ kÃ½. Kiá»ƒm tra PyNaCl vÃ  key.")

    def _update_appcast(self):
        version = self.version_var.get().strip()
        sha256 = self.sha256_var.get().strip()
        signature = self.signature_var.get().strip()
        file_size = self.file_size_var.get().strip()
        download_url = self.download_url_var.get().strip()
        build_number = self.build_number_var.get().strip()
        
        missing = []
        if not version: missing.append("Version")
        if not sha256: missing.append("SHA256")
        if not signature: missing.append("Signature")
        if not file_size: missing.append("File size")
        if not download_url: missing.append("Download URL")
        
        if missing:
            messagebox.showerror("Lá»—i", f"Thiáº¿u: {', '.join(missing)}")
            return
        
        if not messagebox.askyesno("XÃ¡c nháº­n", f"Cáº­p nháº­t appcast.xml cho v{version}?"):
            return
        
        self._set_status("â³ Äang cáº­p nháº­t appcast...")
        if update_appcast_xml(self.appcast_path, version, download_url, sha256, signature,
                             int(file_size), self.release_notes_var.get(), self.title_var.get(),
                             build_number):
            self._set_status("âœ… ÄÃ£ cáº­p nháº­t appcast.xml")
            messagebox.showinfo("OK", "ÄÃ£ cáº­p nháº­t appcast.xml!")
        else:
            messagebox.showerror("Lá»—i", "KhÃ´ng thá»ƒ cáº­p nháº­t")
    
    def _git_status(self):
        try:
            result = subprocess.run(['git', 'status'], capture_output=True, text=True, cwd=self.work_dir)
            messagebox.showinfo("Git Status", result.stdout if result.returncode == 0 else result.stderr)
        except Exception as e:
            messagebox.showerror("Lá»—i", str(e))
    
    def _git_commit_push(self):
        version = self.version_var.get().strip()
        if not version:
            return
        if not messagebox.askyesno("XÃ¡c nháº­n", f"Commit & Push cho v{version}?"):
            return
        self._set_status("â³ Äang push...")
        success, msg = git_commit_and_push(self.work_dir, version, [self.appcast_path])
        self._set_status("âœ… ÄÃ£ push!" if success else "âŒ Lá»—i push")
        if success:
            messagebox.showinfo("Káº¿t quáº£", msg)
        else:
            messagebox.showerror("Lá»—i", msg)


def main():
    root = tk.Tk()
    app = ReleaseManagerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

