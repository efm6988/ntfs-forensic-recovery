
# NTFS Forensic Recovery (Windows 11 x64)

GUI app for scanning NTFS images/devices, optional USN extraction, RAW file carving, and ZIP reconstruction.

## How to build (in the cloud)

1. Push this repo to GitHub (branch `main`).
2. Go to **Actions** → select **Build Windows App (Portable + Installer)** → **Run workflow** (or push to trigger).
3. When it finishes:
   - Download artifact **portable-onefolder** (recommended).
   - (Optional) Download **portable-onefile** (single EXE).
   - (Optional) Download **installer** (Windows installer).

> No Python is needed on your PC. The build runs in GitHub Actions and bundles Python into the app.

## How to run (portable one-folder)

1. Unzip `NTFSForensicRecovery-portable-onefolder.zip`.
2. Right-click `NTFSForensicRecovery.exe` → **Run as administrator** (recommended for raw devices and $UsnJrnl).
3. Choose **Source** and **Destination** → click **START FULL RECOVERY**.

## How to install

1. Download the **installer** artifact.
2. Run the installer `.exe`.
3. Launch from the Start menu (use “Run as administrator” when needed).

## Notes

- For **physical devices** (e.g., `\\.\PhysicalDrive0`) or accessing `\$Extend\$UsnJrnl:$J`, **Run as administrator**.
- For safer testing, use an **NTFS image file** rather than a live disk.
- The workflow targets **Python 3.10** to ensure `pytsk3` wheels install smoothly.
- If you add your own icon, place a proper ICO at `assets/app.ico`. The build will validate/convert it; otherwise it will generate a placeholder icon.
