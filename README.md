# Directory Size Analyzer

A fast, real-time directory size analysis tool built with Python's standard library.

## Features

- **Fast scanning**: Uses `os.scandir()` for efficient directory traversal (3x faster than `dir /s` on Windows!)
- **Real-time updates**: See the tree build as scanning progresses
- **Two size metrics**: Shows both total size (including subdirectories) and exclusive size (files only at each level)
- **Automatic sorting**: Directories automatically sorted by size (largest first) during scanning
- **Right-click context menu**:
  - Browse folder in file explorer
  - Refresh individual folders to rescan them
- **Safe**: Does not follow symbolic links (prevents infinite loops)
- **Multi-process**: Scanner and GUI run in separate processes to avoid blocking
- **Cross-platform**: Works on Windows, macOS, and Linux
- **Standard library only**: No external dependencies required

## Performance

Based on benchmark testing:
- **180k files, 50k directories**: ~1.3 seconds
- **Comparison**: 3x faster than Windows `dir /s /-c /a:-d` command

## Requirements

- Python 3.9.13 or higher
- Windows 11 (or any OS with tkinter support)
- Standard library only - no pip installs needed!

## Installation

No installation needed! Just copy the files:
- `main.py` - Entry point
- `gui.py` - GUI implementation
- `scanner.py` - Directory scanner

## Usage

1. Run the application:
   ```bash
   python main.py
   ```

2. Use the GUI:
   - Click **Browse** or type a path directly
   - Click **Scan** to start analyzing
   - Watch the tree build in real-time with automatic sorting
   - View **Total Size** (includes all subdirectories) and **Exclusive Size** (files only at each level)
   - Right-click any folder to:
     - **Browse Folder**: Open it in your file explorer
     - **Refresh**: Rescan just that folder to update its contents
   - Click **Stop** to cancel a scan in progress

## How It Works

### Architecture

```
Scanner Process                    GUI Process
---------------                    -----------
os.scandir() ──────────────────>  Tree Widget
  │                  Queue
  │ (depth-first)              
  ├─ child dirs first
  └─ parent dirs last
  
  Buffer: 0.1s chunks
```

### Data Flow

1. **Scanner** traverses directories depth-first (children before parents)
2. For each directory, collects its **exclusive size** (files only, not subdirs)
3. Buffers results for 0.1 seconds, then sends batch via queue
4. **GUI** receives batches and for each `(path, size)`:
   - Creates missing tree nodes
   - Sets the directory's size
   - Propagates size up to all ancestors
5. User sees progressive updates as each batch arrives

### Why This Approach?

**Depth-first traversal** means:
- Children are processed before their parents
- When we receive a directory's size, we just add it to existing parent totals
- Simple accumulation logic in the GUI
- Natural tree-building order

**Time-based buffering** (0.1s) means:
- Not sending one message per directory (too slow)
- Not waiting for entire scan (no real-time updates)
- Sweet spot: smooth updates without overwhelming the GUI

**Exclusive sizes** mean:
- Each directory reports only its direct files
- Total size = exclusive size + all descendant exclusive sizes
- Clean separation of concerns

## File Structure

```
main.py       - Entry point (start here)
scanner.py    - Scanner process (os.scandir traversal)
gui.py        - GUI implementation (tkinter tree widget)
```

## Technical Details

### Scanner Process
- Uses `os.scandir()` with `follow_symlinks=False`
- Recursive depth-first traversal
- Accumulates file sizes per directory
- Buffers results for 0.1 seconds before sending
- Gracefully handles permission errors

### GUI Process
- Tkinter Treeview widget with two size columns
- Polls queue every 50ms
- Creates tree nodes on-demand (only within scan root)
- Tracks both total size and exclusive size for each directory
- Propagates total sizes up ancestor chain
- Automatically sorts children by total size (descending)
- Formats sizes in human-readable format (B, KB, MB, GB, TB)
- Right-click context menu for folder operations
- Refresh functionality recomputes ancestor sizes correctly

### Inter-Process Communication
- `multiprocessing.Queue` for data transfer
- `multiprocessing.Event` for stop signaling
- Messages: `('START', path)`, `[(path, size), ...]`, `'DONE'`, `('ERROR', msg)`

## Known Limitations

- Very deep directory hierarchies (1000+ levels) may hit recursion limits
- No filtering options yet
- Tree only shows scanned directory and its children (no ancestor nodes)
- Cannot refresh while a scan is in progress

## Future Enhancements

Possible improvements:
- Filter by file types or size thresholds
- Export to CSV/JSON
- Search functionality
- Directory comparison mode
- Duplicate file detection
- Manual column sorting (currently auto-sorts by total size)
- Size change indicators after refresh
- Allow concurrent refresh of multiple folders

## Troubleshooting

**"Permission denied" errors**: Normal - the scanner skips inaccessible directories

**GUI freezes**: Should not happen due to multi-process architecture. If it does, click Stop and restart.

**Incorrect sizes**: Make sure you're not scanning while files are being actively modified.

## License

Use freely for any purpose.

## Credits

Built as a demonstration of efficient directory scanning techniques in Python.
