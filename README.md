# ntfs-forensic-recovery

# NTFS Forensic Recovery (Windows 11 x64)

GUI app for scanning NTFS images/devices, optional USN extraction, RAW file carving, and ZIP reconstruction.

## How to run (portable)
1. Download artifact **portable-onefolder** from GitHub Actions.
2. Unzip.
3. Right-click `NTFSForensicRecovery.exe` → Run as administrator (recommended for raw devices).

## How to install
1. Download artifact **installer**.
2. Run the installer `.exe`.
3. Launch from Start menu.

## Notes
- For physical drives (e.g. `\\.\PhysicalDrive0`) or `$UsnJrnl` access, run as **administrator**.
- For safer testing, use an NTFS **image file** instead of a live disk.
