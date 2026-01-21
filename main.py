
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, os, struct, hashlib, zipfile, io

try:
    import pytsk3
    HAS_PYTSK3 = True
except ImportError:
    HAS_PYTSK3 = False

FILE_SIGNATURES = {
    b"\x50\x4B\x03\x04": ".zip",
    b"\xff\xd8\xff": ".jpg",
    b"\x89PNG": ".png",
    b"%PDF": ".pdf",
}

MAX_CARVE_SIZE = 50 * 1024 * 1024  # 50MB safety cap


class NTFSForensicGUI:
    def __init__(self, root):
        self.root = root
        root.title("NTFS Forensic Recovery Suite")
        root.geometry("900x650")

        self.src = tk.StringVar()
        self.dst = tk.StringVar()
        self.scan_deleted = tk.BooleanVar(value=True)
        self.carve = tk.BooleanVar(value=True)
        self.usn = tk.BooleanVar(value=True)
        self.rebuild_zip = tk.BooleanVar(value=True)

        ttk.Label(root, text="NTFS Forensic Recovery Suite", font=("Segoe UI", 16, "bold")).pack(pady=10)

        frm = ttk.Frame(root, padding=10)
        frm.pack(fill="x")

        ttk.Label(frm, text="Source (Image or \\\\.\\PhysicalDriveX)").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.src, width=75).grid(row=1, column=0)
        ttk.Button(frm, text="Browse", command=self.browse_src).grid(row=1, column=1)

        ttk.Label(frm, text="Destination Folder").grid(row=2, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(frm, textvariable=self.dst, width=75).grid(row=3, column=0)
        ttk.Button(frm, text="Browse", command=self.browse_dst).grid(row=3, column=1)

        opt = ttk.LabelFrame(root, text="Recovery Options", padding=10)
        opt.pack(fill="x", padx=10)
        ttk.Checkbutton(opt, text="Recover Deleted Files (MFT Scan)", variable=self.scan_deleted).pack(anchor="w")
        ttk.Checkbutton(opt, text="File Carving (RAW)", variable=self.carve).pack(anchor="w")
        ttk.Checkbutton(opt, text="Extract NTFS Journal ($UsnJrnl)", variable=self.usn).pack(anchor="w")
        ttk.Checkbutton(opt, text="ZIP Reconstruction", variable=self.rebuild_zip).pack(anchor="w")

        self.progress = ttk.Progressbar(root)
        self.progress.pack(fill="x", padx=10, pady=10)

        self.log = tk.Text(root, height=18, font=("Consolas", 9), state="disabled")
        self.log.pack(fill="both", expand=True, padx=10)

        ttk.Button(root, text="START FULL RECOVERY", command=self.start).pack(pady=10)

    def browse_src(self):
        p = filedialog.askopenfilename()
        if p:
            self.src.set(p)

    def browse_dst(self):
        p = filedialog.askdirectory()
        if p:
            self.dst.set(p)

    def write(self, msg):
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def start(self):
        if not self.src.get() or not self.dst.get():
            messagebox.showerror("Error", "Select source and destination")
            return
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        img = pytsk3.Img_Info(self.src.get())
        fs = pytsk3.FS_Info(img)

        self.write("[*] Scanning all MFT records...")
        recovered = 0

        for inode in range(fs.info.first_inum, fs.info.last_inum):
            try:
                entry = fs.open_meta(inode=inode)
                if not entry.info.meta or entry.info.meta.size <= 0:
                    continue

                deleted = entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC
                if deleted and not self.scan_deleted.get():
                    continue

                name = entry.info.name.name.decode(errors="ignore") if entry.info.name else f"inode_{inode}"
                folder = "deleted" if deleted else "allocated"
                outdir = os.path.join(self.dst.get(), folder)
                os.makedirs(outdir, exist_ok=True)

                path = os.path.join(outdir, name)
                self.reassemble_file(entry, path)

                recovered += 1
                if recovered % 100 == 0:
                    self.write(f"[+] {recovered} files recovered")

            except Exception:
                pass

            self.progress["value"] = (inode / fs.info.last_inum) * 100

        if self.usn.get():
            self.extract_usn(fs)

        if self.carve.get():
            self.carve_raw()

        if self.rebuild_zip.get():
            self.rebuild_zips()

        self.write("[✓] RECOVERY COMPLETE")
        messagebox.showinfo("Done", "Recovery completed")

    # ---------------- FORENSIC CORE ----------------

    def reassemble_file(self, entry, outpath):
        with open(outpath, "wb") as f:
            offset = 0
            size = entry.info.meta.size
            while offset < size:
                data = entry.read_random(offset, min(1024 * 1024, size - offset))
                if not data:
                    break
                f.write(data)
                offset += len(data)

    def extract_usn(self, fs):
        self.write("[*] Extracting NTFS $UsnJrnl (best-effort)")
        try:
            usn = fs.open("/$Extend/$UsnJrnl:$J")
            out = os.path.join(self.dst.get(), "usn_journal.bin")
            with open(out, "wb") as f:
                f.write(usn.read_random(0, usn.info.meta.size))
            self.write("[+] USN Journal extracted")
        except Exception:
            self.write("[!] USN Journal not accessible")

    def carve_raw(self):
        self.write("[*] Starting RAW carving...")
        with open(self.src.get(), "rb") as f:
            data = f.read()

        out = os.path.join(self.dst.get(), "carved")
        os.makedirs(out, exist_ok=True)
        count = 0

        for sig, ext in FILE_SIGNATURES.items():
            pos = 0
            while True:
                pos = data.find(sig, pos)
                if pos == -1:
                    break
                path = os.path.join(out, f"carved_{count}{ext}")
                with open(path, "wb") as o:
                    o.write(data[pos:pos + MAX_CARVE_SIZE])
                count += 1
                pos += len(sig)

        self.write(f"[+] RAW carved {count} files")

    def rebuild_zips(self):
        self.write("[*] Attempting ZIP reconstruction...")
        carved = os.path.join(self.dst.get(), "carved")
        if not os.path.exists(carved):
            return

        rebuilt = os.path.join(self.dst.get(), "rebuilt_zip")
        os.makedirs(rebuilt, exist_ok=True)

        for f in os.listdir(carved):
            if f.endswith(".zip"):
                try:
                    data = open(os.path.join(carved, f), "rb").read()
                    z = zipfile.ZipFile(io.BytesIO(data))
                    z.extractall(os.path.join(rebuilt, f))
                    self.write(f"[+] Rebuilt ZIP: {f}")
                except Exception:
                    pass


if __name__ == "__main__":
    root = tk.Tk()
    NTFSForensicGUI(root)
    root.mainloop()
