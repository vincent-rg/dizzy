"""
Directory scanner process.
Scans directories using os.scandir and sends results via queue.
"""
import os
import time
from multiprocessing import Queue


def scan_directory_tree(root_path, result_queue, stop_event):
    """
    Scan directory tree and send results to queue in batches.
    
    Args:
        root_path: Root directory to scan
        result_queue: Queue to send results
        stop_event: Event to signal stop request
    """
    buffer = []
    last_send_time = time.perf_counter()
    
    def send_buffer():
        """Send current buffer to queue and clear it."""
        nonlocal last_send_time
        if buffer:
            result_queue.put(buffer[:])
            buffer.clear()
            last_send_time = time.perf_counter()
    
    def scan_recursive(path):
        """
        Recursively scan directory.
        Returns exclusive size of this directory (files only, not subdirs).
        """
        if stop_event.is_set():
            return 0
        
        exclusive_size = 0
        
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    if stop_event.is_set():
                        return exclusive_size
                    
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            # Recurse into subdirectory first (depth-first)
                            scan_recursive(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            # Add file size to this directory's exclusive size
                            stat_info = entry.stat(follow_symlinks=False)
                            exclusive_size += stat_info.st_size
                    except (PermissionError, OSError):
                        # Skip inaccessible files/directories
                        continue
        except (PermissionError, OSError):
            # Skip inaccessible directories
            return exclusive_size
        
        # Add this directory to buffer with its exclusive size
        buffer.append((path, exclusive_size))
        
        # Send buffer if 0.1 seconds elapsed
        current_time = time.perf_counter()
        if current_time - last_send_time >= 0.1:
            send_buffer()
        
        return exclusive_size
    
    try:
        # Start scanning
        result_queue.put(('START', root_path))
        scan_recursive(root_path)
        
        # Send any remaining buffered data
        send_buffer()
        
        # Signal completion
        result_queue.put('DONE')
    except Exception as e:
        result_queue.put(('ERROR', str(e)))
