"""
Directory Size Analyzer
========================

A tool to analyze directory structures and display file sizes in a tree view.

Features:
- Fast directory scanning using os.scandir
- Real-time updates as scanning progresses
- Does not follow symbolic links
- Multi-process architecture (scanner + GUI)
- Shows total size for each directory (including subdirectories)

Usage:
    python main.py

Requirements:
    - Python 3.9.13+
    - Windows 11 (or any OS with tkinter support)
    - Standard library only

Architecture:
    - Scanner process: Traverses directories depth-first using os.scandir
    - GUI process: Displays tree and updates in real-time
    - Communication: multiprocessing.Queue with 0.1s buffering
"""

if __name__ == "__main__":
    # Import here to handle multiprocessing properly on Windows
    from gui import main
    main()
