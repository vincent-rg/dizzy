"""
GUI for directory tree viewer.
Displays directory tree with sizes using tkinter.
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from multiprocessing import Process, Queue, Event
from scanner import scan_directory_tree


def format_size(bytes_size):
    """Format bytes into human-readable format."""
    if bytes_size == 0:
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


class DirectoryTreeViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("Directory Size Analyzer")
        self.root.geometry("900x600")
        
        # Data structures
        self.path_to_node = {}  # Maps path -> tree node id
        self.node_sizes = {}    # Maps node id -> current total size
        self.node_exclusive_sizes = {}  # Maps node id -> exclusive size (files only at this level)
        
        # Multiprocessing
        self.result_queue = None
        self.scanner_process = None
        self.stop_event = None
        
        # Statistics
        self.scan_start_time = None
        self.total_processed = 0
        
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
                                 xscrollcommand=hsb.set)
        
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
        self.tree.tag_configure('directory', foreground='#0066cc')
    
    def browse_directory(self):
        """Open directory browser dialog."""
        directory = filedialog.askdirectory()
        if directory:
            self.path_var.set(directory)
    
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
        
        # Setup multiprocessing
        self.result_queue = Queue()
        self.stop_event = Event()
        
        # Start scanner process
        self.scanner_process = Process(
            target=scan_directory_tree,
            args=(path, self.result_queue, self.stop_event)
        )
        self.scanner_process.start()
        
        # Update UI state
        self.scan_btn.config(state=tk.DISABLED)
        self.browse_btn.config(state=tk.DISABLED)
        self.path_entry.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        self.scan_start_time = None
        self.status_var.set("Starting scan...")
        
        # Start polling queue
        self.root.after(50, self.poll_queue)
    
    def stop_scan(self):
        """Stop the scanning process."""
        if self.stop_event:
            self.stop_event.set()
        self.status_var.set("Stopping scan...")
    
    def poll_queue(self):
        """Poll queue for results from scanner process."""
        if self.result_queue is None:
            return
        
        # Process all available items in queue
        items_processed = 0
        max_items_per_poll = 10  # Process up to 10 batches per poll
        
        while items_processed < max_items_per_poll:
            try:
                result = self.result_queue.get_nowait()
                
                if result == 'DONE':
                    self.finish_scan(success=True)
                    return
                elif isinstance(result, tuple) and result[0] == 'START':
                    self.scan_start_time = __import__('time').perf_counter()
                    self.status_var.set(f"Scanning: {result[1]}")
                elif isinstance(result, tuple) and result[0] == 'ERROR':
                    self.finish_scan(success=False, error=result[1])
                    return
                elif isinstance(result, list):
                    # Process batch of (path, size) tuples
                    self.process_batch(result)
                    items_processed += 1
                
            except:
                # Queue empty
                break
        
        # Continue polling if scan is active
        if self.scanner_process and self.scanner_process.is_alive():
            self.root.after(50, self.poll_queue)
        else:
            # Process ended unexpectedly
            self.finish_scan(success=False, error="Scanner process ended unexpectedly")
    
    def process_batch(self, batch):
        """Process a batch of (path, size) tuples."""
        for path, size in batch:
            self.add_or_update_node(path, size)
            self.total_processed += 1
        
        # Update status
        elapsed = __import__('time').perf_counter() - self.scan_start_time if self.scan_start_time else 0
        self.status_var.set(f"Scanning... {self.total_processed:,} directories processed ({elapsed:.1f}s)")
    
    def add_or_update_node(self, path, exclusive_size):
        """
        Add or update a node in the tree.
        Creates missing parent nodes and propagates size upward.
        """
        # Normalize path
        path = os.path.normpath(path)

        # Get or create node for this path
        if path in self.path_to_node:
            node_id = self.path_to_node[path]
        else:
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
        """Create a node and all its missing ancestors."""
        # Check if already exists
        if path in self.path_to_node:
            return self.path_to_node[path]
        
        # Get parent path
        parent_path = os.path.dirname(path)
        
        # Create parent if needed and not at root
        if parent_path and parent_path != path:
            parent_id = self.create_node(parent_path)
        else:
            parent_id = ''
        
        # Get display name
        if parent_path and parent_path != path:
            name = os.path.basename(path)
        else:
            name = path  # Root node shows full path
        
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

        # Sort siblings by total size (descending)
        parent_id = self.tree.parent(node_id)
        self.sort_children(parent_id)
    
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
            messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error}")


def main():
    root = tk.Tk()
    app = DirectoryTreeViewer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
