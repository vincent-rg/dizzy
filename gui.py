"""
GUI for directory tree viewer.
Displays directory tree with sizes using tkinter.
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import subprocess
import platform
from multiprocessing import Process, Queue, Event
from scanner import scan_directory_tree
from enum import Enum
import logging
import shutil

# Setup logging (WARNING level for production)
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')


class ScanMode(Enum):
    """Mode for scanning operations."""
    IDLE = "idle"
    INITIAL_SCAN = "initial_scan"
    REFRESH = "refresh"


def format_size(bytes_size):
    """Format bytes into human-readable format."""
    if bytes_size == 0:
        return "0 B"

    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


def handle_remove_readonly(func, path, exc_info):
    """
    Error handler for shutil.rmtree to handle read-only and protected files.
    This allows deletion of files that Windows Explorer can delete without admin rights.
    """
    import stat

    # Check if the error is a permission error
    excvalue = exc_info[1]
    if isinstance(excvalue, PermissionError):
        # Try to make the file writable by removing read-only attribute
        try:
            os.chmod(path, stat.S_IWUSR | stat.S_IRUSR)
            # Retry the failed operation
            func(path)
        except Exception:
            # If we still can't delete it, re-raise the original exception
            raise excvalue
    else:
        # For other errors, re-raise
        raise excvalue


class DirectoryTreeViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("Directory Size Analyzer")
        self.root.geometry("900x600")
        
        # Data structures
        self.path_to_node = {}  # Maps path -> tree node id
        self.node_sizes = {}    # Maps node id -> current total size
        self.node_exclusive_sizes = {}  # Maps node id -> exclusive size (files only at this level)
        self.scan_root = None  # The root directory being scanned
        
        # Multiprocessing
        self.result_queue = None
        self.scanner_process = None
        self.stop_event = None
        self.scan_mode = ScanMode.IDLE

        # Refresh state
        self.refresh_node_id = None
        self.refresh_path = None
        self.refresh_new_total_size = 0
        self.refresh_new_exclusive_size = 0
        self.refresh_queue = []  # Queue of folders to refresh (for multi-folder refresh)

        # Statistics
        self.scan_start_time = None
        self.total_processed = 0

        # Performance optimization
        self.affected_parents = set()  # Track parents that need sorting after batch
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create GUI widgets."""
        # Top frame with controls
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X)
        
        ttk.Label(top_frame, text="Path:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(top_frame, textvariable=self.path_var, width=60)
        self.path_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        self.browse_btn = ttk.Button(top_frame, text="Browse", command=self.browse_directory)
        self.browse_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.scan_btn = ttk.Button(top_frame, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_btn = ttk.Button(top_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)
        
        # Status bar
        status_frame = ttk.Frame(self.root, padding="5 0 5 5")
        status_frame.pack(fill=tk.X)

        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT)

        # Disk space frame
        disk_frame = ttk.Frame(self.root, padding="5 0 5 5")
        disk_frame.pack(fill=tk.X)

        self.disk_space_var = tk.StringVar(value="")
        self.disk_space_label = ttk.Label(disk_frame, textvariable=self.disk_space_var)
        self.disk_space_label.pack(side=tk.LEFT, padx=(0, 5))

        self.refresh_disk_btn = ttk.Button(disk_frame, text="Refresh Free Space", command=self.refresh_disk_space)
        self.refresh_disk_btn.pack(side=tk.LEFT)

        # Tree frame with scrollbars
        tree_frame = ttk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        
        # Tree widget
        self.tree = ttk.Treeview(tree_frame,
                                 columns=('total_size', 'exclusive_size', 'total_size_bytes', 'exclusive_size_bytes'),
                                 yscrollcommand=vsb.set,
                                 xscrollcommand=hsb.set,
                                 selectmode='extended')
        
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        
        # Layout
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Tree columns
        self.tree.heading('#0', text='Directory', anchor=tk.W)
        self.tree.heading('total_size', text='Total Size', anchor=tk.E)
        self.tree.heading('exclusive_size', text='Exclusive Size', anchor=tk.E)

        self.tree.column('#0', width=500, minwidth=200)
        self.tree.column('total_size', width=150, anchor=tk.E)
        self.tree.column('exclusive_size', width=150, anchor=tk.E)
        self.tree.column('total_size_bytes', width=0, stretch=False)  # Hidden column for sorting
        self.tree.column('exclusive_size_bytes', width=0, stretch=False)  # Hidden column for sorting

        # Configure tags for styling
        self.tree.tag_configure('directory', foreground='#000000')

        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Browse Folder", command=self.browse_folder_context)
        self.context_menu.add_command(label="Open in Terminal", command=self.open_terminal_context)
        self.context_menu.add_command(label="Refresh", command=self.refresh_folder_context)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete Folder", command=self.delete_folder_context)

        # Bind right-click
        self.tree.bind("<Button-3>", self.show_context_menu)
    
    def browse_directory(self):
        """Open directory browser dialog."""
        directory = filedialog.askdirectory()
        if directory:
            self.path_var.set(directory)

    def get_disk_space(self, path):
        """Get free disk space for the drive containing the given path."""
        try:
            if not path or not os.path.exists(path):
                return None

            # Get disk usage statistics
            stat = shutil.disk_usage(path)
            return {
                'total': stat.total,
                'used': stat.used,
                'free': stat.free
            }
        except Exception as e:
            logging.error(f"Error getting disk space for {path}: {e}")
            return None

    def update_disk_space_display(self):
        """Update the disk space display for the current scan root."""
        if not self.scan_root:
            self.disk_space_var.set("")
            return

        disk_info = self.get_disk_space(self.scan_root)
        if disk_info:
            free_space = format_size(disk_info['free'])
            total_space = format_size(disk_info['total'])
            used_space = format_size(disk_info['used'])
            percent_used = (disk_info['used'] / disk_info['total'] * 100) if disk_info['total'] > 0 else 0

            self.disk_space_var.set(
                f"Drive: {os.path.splitdrive(self.scan_root)[0] or '/'} | "
                f"Free: {free_space} | Used: {used_space} / {total_space} ({percent_used:.1f}%)"
            )
        else:
            self.disk_space_var.set("Unable to get disk space information")

    def refresh_disk_space(self):
        """Refresh the disk space display."""
        self.update_disk_space_display()

    def start_scan(self):
        """Start scanning process."""
        path = self.path_var.get().strip()
        
        if not path:
            messagebox.showwarning("No Path", "Please enter or select a directory path.")
            return
        
        if not os.path.exists(path):
            messagebox.showerror("Invalid Path", f"Path does not exist: {path}")
            return
        
        if not os.path.isdir(path):
            messagebox.showerror("Invalid Path", "Path must be a directory.")
            return
        
        # Clear previous results
        self.tree.delete(*self.tree.get_children())
        self.path_to_node.clear()
        self.node_sizes.clear()
        self.node_exclusive_sizes.clear()
        self.total_processed = 0
        self.scan_root = os.path.normpath(path)
        self.affected_parents.clear()

        # Update disk space display
        self.update_disk_space_display()

        # Setup multiprocessing
        self.result_queue = Queue()
        self.stop_event = Event()
        
        # Start scanner process
        self.scanner_process = Process(
            target=scan_directory_tree,
            args=(path, self.result_queue, self.stop_event)
        )
        self.scanner_process.start()
        self.scan_mode = ScanMode.INITIAL_SCAN

        # Update UI state
        self.scan_btn.config(state=tk.DISABLED)
        self.browse_btn.config(state=tk.DISABLED)
        self.path_entry.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        self.scan_start_time = None
        self.status_var.set("Starting scan...")

        # Start polling queue
        self.root.after(20, self.poll_scanner_queue)
    
    def stop_scan(self):
        """Stop the scanning process."""
        if self.stop_event:
            self.stop_event.set()
        self.status_var.set("Stopping scan...")

    def poll_scanner_queue(self):
        """Generic queue polling method for both initial scan and refresh."""
        if self.result_queue is None:
            return

        # Process only ONE batch per poll for smoother updates
        try:
            result = self.result_queue.get_nowait()

            if result == 'DONE':
                # Finish based on mode
                if self.scan_mode == ScanMode.INITIAL_SCAN:
                    self.finish_scan(success=True)
                elif self.scan_mode == ScanMode.REFRESH:
                    self.finish_refresh(success=True)
                return

            elif isinstance(result, tuple) and result[0] == 'START':
                if self.scan_mode == ScanMode.INITIAL_SCAN:
                    self.scan_start_time = __import__('time').perf_counter()
                    self.status_var.set(f"Scanning: {result[1]}")
                # Ignore START for refresh

            elif isinstance(result, tuple) and result[0] == 'ERROR':
                # Finish based on mode
                if self.scan_mode == ScanMode.INITIAL_SCAN:
                    self.finish_scan(success=False, error=result[1])
                elif self.scan_mode == ScanMode.REFRESH:
                    self.finish_refresh(success=False, error=result[1])
                return

            elif isinstance(result, list):
                # Clear affected parents for batch sorting
                self.affected_parents.clear()

                # Process batch based on mode
                if self.scan_mode == ScanMode.INITIAL_SCAN:
                    for path, size in result:
                        self.add_or_update_node(path, size)
                        self.total_processed += 1
                    # Update status
                    elapsed = __import__('time').perf_counter() - self.scan_start_time if self.scan_start_time else 0
                    self.status_var.set(f"Scanning... {self.total_processed:,} directories processed ({elapsed:.1f}s)")

                elif self.scan_mode == ScanMode.REFRESH:
                    for scan_path, exclusive_size in result:
                        scan_path = os.path.normpath(scan_path)
                        if scan_path == self.refresh_path:
                            # This is the root of the refresh
                            self.refresh_new_exclusive_size += exclusive_size
                            self.refresh_new_total_size += exclusive_size
                        else:
                            # Subdirectory - add as child
                            self.add_or_update_node(scan_path, exclusive_size)
                            self.refresh_new_total_size += exclusive_size

                # Sort all affected parents once after batch
                for parent_id in self.affected_parents:
                    self.sort_children(parent_id)

        except:
            # Queue empty - this is normal
            pass

        # Continue polling if scan is active OR if process just finished (queue may still have items)
        if self.scanner_process:
            self.root.after(20, self.poll_scanner_queue)

    def add_or_update_node(self, path, exclusive_size):
        """
        Add or update a node in the tree.
        Creates missing parent nodes and propagates size upward.
        """
        # Normalize path
        path = os.path.normpath(path)

        # Get or create node for this path
        if path in self.path_to_node and self.path_to_node[path] is not None:
            # Existing valid node
            node_id = self.path_to_node[path]
        else:
            # Either doesn't exist or is marked as deleted (None)
            node_id = self.create_node(path)

        # Update exclusive size for this node
        current_exclusive_size = self.node_exclusive_sizes.get(node_id, 0)
        new_exclusive_size = current_exclusive_size + exclusive_size
        self.node_exclusive_sizes[node_id] = new_exclusive_size

        # Update total size for this node
        current_total_size = self.node_sizes.get(node_id, 0)
        new_total_size = current_total_size + exclusive_size
        self.node_sizes[node_id] = new_total_size

        # Update display
        self.update_node_display(node_id, new_total_size, new_exclusive_size)

        # Propagate size to all ancestors
        self.propagate_size_to_ancestors(path, exclusive_size)
    
    def create_node(self, path):
        """Create a node and all its missing ancestors up to scan_root."""
        # Normalize path first
        path = os.path.normpath(path)

        # Check if already exists and is valid (not marked as deleted)
        if path in self.path_to_node and self.path_to_node[path] is not None:
            return self.path_to_node[path]

        # If this is the scan root, create it at tree root
        if path == self.scan_root:
            # Root node shows full path
            node_id = self.tree.insert('', 'end', text=path, values=('0 B', '0 B', 0, 0), tags=('directory',))
            self.path_to_node[path] = node_id
            self.node_sizes[node_id] = 0
            self.node_exclusive_sizes[node_id] = 0
            return node_id

        # Get parent path
        parent_path = os.path.dirname(path)

        # Check if path is within scan_root
        if not path.startswith(self.scan_root):
            # This shouldn't happen, but handle gracefully
            return None

        # Create parent if needed
        if parent_path and parent_path != path:
            parent_id = self.create_node(parent_path)
            if parent_id is None:
                return None
        else:
            parent_id = ''

        # Get display name (just the folder name, not full path)
        name = os.path.basename(path)

        # Create tree node
        node_id = self.tree.insert(parent_id, 'end', text=name, values=('0 B', '0 B', 0, 0), tags=('directory',))

        # Store mapping
        self.path_to_node[path] = node_id
        self.node_sizes[node_id] = 0
        self.node_exclusive_sizes[node_id] = 0

        return node_id
    
    def update_node_display(self, node_id, total_size, exclusive_size):
        """Update the display of a node with new sizes."""
        self.tree.item(node_id, values=(format_size(total_size), format_size(exclusive_size), total_size, exclusive_size))

        # Track parent for batch sorting (sorted once per batch in process_batch)
        parent_id = self.tree.parent(node_id)
        if parent_id or parent_id == '':  # Include root children
            self.affected_parents.add(parent_id)
    
    def sort_children(self, parent_id):
        """Sort children of a parent node by total size (descending)."""
        children = self.tree.get_children(parent_id)
        if not children:
            return

        # Create list of (child_id, total_size) tuples
        children_with_sizes = []
        for child_id in children:
            total_size = self.node_sizes.get(child_id, 0)
            children_with_sizes.append((child_id, total_size))

        # Sort by total size descending
        children_with_sizes.sort(key=lambda x: x[1], reverse=True)

        # Reorder children in tree
        for index, (child_id, _) in enumerate(children_with_sizes):
            self.tree.move(child_id, parent_id, index)

    def propagate_size_to_ancestors(self, path, size_delta):
        """Propagate size delta to all ancestor nodes (total size only, not exclusive)."""
        current_path = path

        while True:
            parent_path = os.path.dirname(current_path)

            # Stop if we're at the scan root
            if current_path == self.scan_root:
                break

            # Stop if we're at the root or no parent
            if not parent_path or parent_path == current_path:
                break

            # Update parent's total size (exclusive size stays unchanged)
            if parent_path in self.path_to_node:
                parent_id = self.path_to_node[parent_path]
                current_total_size = self.node_sizes.get(parent_id, 0)
                new_total_size = current_total_size + size_delta
                self.node_sizes[parent_id] = new_total_size

                # Get current exclusive size (doesn't change during propagation)
                exclusive_size = self.node_exclusive_sizes.get(parent_id, 0)
                self.update_node_display(parent_id, new_total_size, exclusive_size)

            current_path = parent_path

    def show_context_menu(self, event):
        """Show context menu on right-click."""
        # Don't show context menu if a scan is in progress
        if self.scan_mode != ScanMode.IDLE:
            return

        # Get the item under cursor
        item = self.tree.identify_row(event.y)
        if not item:
            return

        # If right-clicking on an item that's not in the current selection,
        # clear selection and select just this item
        current_selection = self.tree.selection()
        if item not in current_selection:
            self.tree.selection_set(item)
            current_selection = (item,)

        # Enable/disable menu items based on selection count
        selection_count = len(current_selection)

        # When multiple items are selected, only "Refresh" and "Delete Folder" are enabled
        if selection_count > 1:
            # Disable Browse Folder and Open in Terminal
            self.context_menu.entryconfig(0, state=tk.DISABLED)  # Browse Folder
            self.context_menu.entryconfig(1, state=tk.DISABLED)  # Open in Terminal
            # Enable Refresh and Delete Folder
            self.context_menu.entryconfig(2, state=tk.NORMAL)    # Refresh
            self.context_menu.entryconfig(4, state=tk.NORMAL)    # Delete Folder
        else:
            # Enable all menu items for single selection
            self.context_menu.entryconfig(0, state=tk.NORMAL)    # Browse Folder
            self.context_menu.entryconfig(1, state=tk.NORMAL)    # Open in Terminal
            self.context_menu.entryconfig(2, state=tk.NORMAL)    # Refresh
            self.context_menu.entryconfig(4, state=tk.NORMAL)    # Delete Folder

        self.context_menu.post(event.x_root, event.y_root)

    def get_path_from_node(self, node_id):
        """Get the full path from a tree node."""
        # Find the path by looking up in our path_to_node mapping
        for path, nid in self.path_to_node.items():
            if nid == node_id:
                return path
        return None

    def browse_folder_context(self):
        """Open file explorer at the selected folder."""
        selection = self.tree.selection()
        if not selection:
            return

        node_id = selection[0]
        path = self.get_path_from_node(node_id)

        if path and os.path.exists(path):
            try:
                if platform.system() == 'Windows':
                    os.startfile(path)
                elif platform.system() == 'Darwin':  # macOS
                    subprocess.Popen(['open', path])
                else:  # Linux
                    subprocess.Popen(['xdg-open', path])
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open folder:\n{e}")

    def open_terminal_context(self):
        """Open Windows Terminal at the selected folder."""
        selection = self.tree.selection()
        if not selection:
            return

        node_id = selection[0]
        path = self.get_path_from_node(node_id)

        if path and os.path.exists(path):
            try:
                if platform.system() == 'Windows':
                    # Use Windows Terminal (wt.exe) for Windows 11
                    subprocess.Popen(['wt.exe', '-d', path])
                elif platform.system() == 'Darwin':  # macOS
                    # Use Terminal.app on macOS
                    subprocess.Popen(['open', '-a', 'Terminal', path])
                else:  # Linux
                    # Try common Linux terminals
                    subprocess.Popen(['gnome-terminal', '--working-directory=' + path])
            except FileNotFoundError:
                # Fallback if wt.exe is not found (older Windows)
                if platform.system() == 'Windows':
                    subprocess.Popen(['cmd.exe', '/K', 'cd', '/D', path])
                else:
                    messagebox.showerror("Error", "Could not find terminal application")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open terminal:\n{e}")

    def refresh_folder_context(self):
        """Refresh the selected folder(s) by rescanning them (async)."""
        selection = self.tree.selection()
        if not selection:
            return

        # Don't allow refresh during active scan or another refresh
        if self.scanner_process and self.scanner_process.is_alive():
            if self.refresh_node_id is not None:
                messagebox.showwarning("Refresh in Progress", "Cannot refresh while another refresh is running")
            else:
                messagebox.showwarning("Scan in Progress", "Cannot refresh while a scan is running")
            return

        # Collect valid folders to refresh
        folders_to_refresh = []
        for node_id in selection:
            path = self.get_path_from_node(node_id)

            if not path or not os.path.exists(path):
                continue

            if not os.path.isdir(path):
                continue

            folders_to_refresh.append((node_id, path))

        if not folders_to_refresh:
            messagebox.showerror("Error", "No valid folders to refresh")
            return

        # Initialize refresh queue with all folders
        self.refresh_queue = folders_to_refresh
        logging.info(f"Starting refresh for {len(folders_to_refresh)} folder(s)")

        # Start refreshing the first folder
        self._start_next_refresh()

    def _start_next_refresh(self):
        """Start refreshing the next folder in the refresh queue."""
        if not self.refresh_queue:
            return

        # Get next folder to refresh
        node_id, path = self.refresh_queue.pop(0)

        logging.info(f"Starting refresh for: {path}")

        # Store refresh state
        self.refresh_node_id = node_id
        self.refresh_path = path
        self.refresh_new_total_size = 0
        self.refresh_new_exclusive_size = 0

        # Reset the refresh node's sizes to 0 before rescanning
        self.node_sizes[node_id] = 0
        self.node_exclusive_sizes[node_id] = 0

        # Mark all descendant paths as deleted (fast - just set sentinel value)
        # This invalidates the old node IDs without expensive removal
        for p in list(self.path_to_node.keys()):
            if p.startswith(self.refresh_path + os.sep):
                self.path_to_node[p] = None  # None = deleted marker

        logging.info(f"Marked descendants as deleted in path_to_node")

        # Delete all children from tree (fast - tkinter handles descendants automatically)
        for child in self.tree.get_children(node_id):
            self.tree.delete(child)

        # Note: We intentionally don't clean up node_sizes and node_exclusive_sizes
        # The orphaned entries are harmless and will be overwritten when rescanning

        logging.info(f"Removed all descendants, starting scanner")

        # Setup multiprocessing
        self.result_queue = Queue()
        self.stop_event = Event()

        # Start scanner process
        self.scanner_process = Process(
            target=scan_directory_tree,
            args=(path, self.result_queue, self.stop_event)
        )
        self.scanner_process.start()
        self.scan_mode = ScanMode.REFRESH
        logging.info(f"Refresh scanner process started, mode set to: {self.scan_mode}")

        # Disable scan controls during refresh
        self.scan_btn.config(state=tk.DISABLED)
        self.browse_btn.config(state=tk.DISABLED)
        self.path_entry.config(state=tk.DISABLED)

        remaining = len(self.refresh_queue)
        if remaining > 0:
            self.status_var.set(f"Refreshing: {path} ({remaining} more remaining)")
        else:
            self.status_var.set(f"Refreshing: {path}")

        # Start async polling
        logging.info("Scheduling first poll_scanner_queue call")
        self.root.after(20, self.poll_scanner_queue)

    def delete_folder_context(self):
        """Delete the selected folder(s) permanently."""
        selection = self.tree.selection()
        if not selection:
            return

        # Collect valid folders to delete
        folders_to_delete = []
        total_combined_size = 0

        for node_id in selection:
            path = self.get_path_from_node(node_id)

            if not path or not os.path.exists(path):
                continue

            if not os.path.isdir(path):
                continue

            folder_size = self.node_sizes.get(node_id, 0)
            folders_to_delete.append((node_id, path, folder_size))
            total_combined_size += folder_size

        if not folders_to_delete:
            messagebox.showerror("Error", "No valid folders to delete")
            return

        # Build confirmation message
        if len(folders_to_delete) == 1:
            node_id, path, folder_size = folders_to_delete[0]
            size_str = format_size(folder_size)
            confirm_msg = f"Are you sure you want to permanently delete:\n\n{path}\n\nSize: {size_str}\n\nThis action cannot be undone!"
        else:
            folder_list = "\n".join([f"- {path}" for _, path, _ in folders_to_delete])
            size_str = format_size(total_combined_size)
            confirm_msg = f"Are you sure you want to permanently delete {len(folders_to_delete)} folders:\n\n{folder_list}\n\nTotal Size: {size_str}\n\nThis action cannot be undone!"

        # Confirm deletion
        result = messagebox.askyesno(
            "Confirm Deletion",
            confirm_msg,
            icon='warning'
        )

        if not result:
            return

        # Store original names and update display with " (deleting...)"
        original_names = {}
        for node_id, path, _ in folders_to_delete:
            original_name = os.path.basename(path)
            original_names[node_id] = original_name
            self.tree.item(node_id, text=f"{original_name} (deleting...)")

        # Track all affected parents for size recomputation
        affected_parents_set = set()
        errors = []

        # Delete each folder
        for node_id, path, _ in folders_to_delete:
            try:
                # Delete the folder recursively (efficient)
                # Use onerror handler to remove read-only attributes if needed
                shutil.rmtree(path, onerror=handle_remove_readonly)

                # Get parent before deleting from tree
                parent_id = self.tree.parent(node_id)
                if parent_id or parent_id == '':
                    affected_parents_set.add(parent_id)

                # Remove from tree
                self.tree.delete(node_id)

                # Mark as deleted in path_to_node and all descendants
                paths_to_mark = [p for p in self.path_to_node.keys() if p == path or p.startswith(path + os.sep)]
                for p in paths_to_mark:
                    self.path_to_node[p] = None

            except PermissionError:
                errors.append(f"Permission denied: {path}")
                # Restore original name since folder wasn't deleted
                if node_id in original_names:
                    self.tree.item(node_id, text=original_names[node_id])
            except Exception as e:
                errors.append(f"{path}: {str(e)}")
                # Restore original name since folder wasn't deleted
                if node_id in original_names:
                    self.tree.item(node_id, text=original_names[node_id])

        # Recompute sizes for all affected parents and their ancestors
        processed_parents = set()
        for parent_id in affected_parents_set:
            if parent_id in processed_parents:
                continue

            parent_path = self.get_path_from_node(parent_id)
            if parent_path:
                # Recompute the parent's size directly by summing its children
                parent_exclusive = self.node_exclusive_sizes.get(parent_id, 0)
                children_total = sum(self.node_sizes.get(child_id, 0)
                                    for child_id in self.tree.get_children(parent_id))
                new_parent_total = parent_exclusive + children_total
                self.node_sizes[parent_id] = new_parent_total
                self.update_node_display(parent_id, new_parent_total, parent_exclusive)

                # Then recompute ancestors of the parent
                self.recompute_ancestors_total_size(parent_path)
                processed_parents.add(parent_id)

        # Sort all affected parents after size updates
        for affected_parent_id in self.affected_parents:
            self.sort_children(affected_parent_id)
        self.affected_parents.clear()

        # Update disk space display after deletion
        self.update_disk_space_display()

        # Update status and show errors if any
        if errors:
            error_msg = "\n".join(errors)
            messagebox.showerror("Delete Errors", f"Some folders could not be deleted:\n\n{error_msg}")
            self.status_var.set(f"Deleted {len(folders_to_delete) - len(errors)} of {len(folders_to_delete)} folders")
        else:
            if len(folders_to_delete) == 1:
                self.status_var.set(f"Deleted: {folders_to_delete[0][1]}")
            else:
                self.status_var.set(f"Deleted {len(folders_to_delete)} folders")

    def finish_refresh(self, success=True, error=None):
        """Finish the refresh operation and cleanup."""
        logging.info(f"Finishing refresh, success={success}")

        # Cleanup process
        if self.scanner_process:
            self.scanner_process.join(timeout=1.0)
            if self.scanner_process.is_alive():
                self.scanner_process.terminate()
            self.scanner_process = None

        # Cleanup queue
        self.result_queue = None
        self.stop_event = None

        # Reset scan mode to IDLE
        self.scan_mode = ScanMode.IDLE

        if success:
            # Update the refreshed node's sizes
            self.node_sizes[self.refresh_node_id] = self.refresh_new_total_size
            self.node_exclusive_sizes[self.refresh_node_id] = self.refresh_new_exclusive_size
            self.update_node_display(self.refresh_node_id, self.refresh_new_total_size, self.refresh_new_exclusive_size)

            # Recompute ancestors' total sizes from scratch
            self.recompute_ancestors_total_size(self.refresh_path)

            # Update disk space display after refresh
            self.update_disk_space_display()

            self.status_var.set(f"Refresh complete: {self.refresh_path}")
        else:
            self.status_var.set(f"Refresh failed: {error if error else 'Unknown error'}")
            if error:
                messagebox.showerror("Refresh Error", f"An error occurred during refresh:\n{error}")

        # Clear refresh state for current folder
        self.refresh_node_id = None
        self.refresh_path = None
        self.refresh_new_total_size = 0
        self.refresh_new_exclusive_size = 0

        # Check if there are more folders to refresh
        if self.refresh_queue:
            # Start refreshing the next folder
            logging.info(f"Continuing with next folder in refresh queue ({len(self.refresh_queue)} remaining)")
            self._start_next_refresh()
        else:
            # All refreshes complete - update UI state
            self.scan_btn.config(state=tk.NORMAL)
            self.browse_btn.config(state=tk.NORMAL)
            self.path_entry.config(state=tk.NORMAL)
            logging.info("All refreshes complete")

    def recompute_ancestors_total_size(self, path):
        """Recompute total sizes for all ancestors by summing children."""
        current_path = path

        while True:
            parent_path = os.path.dirname(current_path)

            # Stop if we're at the scan root
            if current_path == self.scan_root:
                break

            # Stop if we're at the root or no parent
            if not parent_path or parent_path == current_path:
                break

            if parent_path in self.path_to_node:
                parent_id = self.path_to_node[parent_path]

                # Recompute parent's total size from exclusive size + all children
                parent_exclusive = self.node_exclusive_sizes.get(parent_id, 0)
                children_total = 0

                for child_id in self.tree.get_children(parent_id):
                    children_total += self.node_sizes.get(child_id, 0)

                new_parent_total = parent_exclusive + children_total
                self.node_sizes[parent_id] = new_parent_total
                self.update_node_display(parent_id, new_parent_total, parent_exclusive)

            current_path = parent_path

    def finish_scan(self, success=True, error=None):
        """Finish the scan and cleanup."""
        # Cleanup process
        if self.scanner_process:
            self.scanner_process.join(timeout=1.0)
            if self.scanner_process.is_alive():
                self.scanner_process.terminate()
            self.scanner_process = None

        # Cleanup queue
        self.result_queue = None
        self.stop_event = None

        # Reset scan mode to IDLE
        self.scan_mode = ScanMode.IDLE

        # Clear affected parents tracking
        self.affected_parents.clear()

        # Update UI state
        self.scan_btn.config(state=tk.NORMAL)
        self.browse_btn.config(state=tk.NORMAL)
        self.path_entry.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

        # Update status
        if success:
            elapsed = __import__('time').perf_counter() - self.scan_start_time if self.scan_start_time else 0
            self.status_var.set(f"Scan complete! {self.total_processed:,} directories processed in {elapsed:.2f}s")
        else:
            self.status_var.set(f"Scan failed: {error if error else 'Unknown error'}")
            if error:
                messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error}")


def main():
    root = tk.Tk()
    app = DirectoryTreeViewer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
