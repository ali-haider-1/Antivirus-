import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import os
import hashlib
import math
import re
import yara

# Compile YARA rules from the file
try:
    rules = yara.compile(filepath='rules.yar')
except yara.SyntaxError as e:
    print(f"Error compiling YARA rules: {e}")
    exit(1)

# Path to the virus database
virus_database_file_path = r'VirusDataBaseHash.bav'

STOP_SIGNAL = "__STOP__"

# Ensure the virus database file exists
if not os.path.exists(virus_database_file_path):
    with open(virus_database_file_path, 'w') as f:
        pass  # Create an empty file if it doesn't exist

# Load hash values from the virus database
def load_virus_database(file_path):
    """Load hash values from the virus database file."""
    virus_hashes = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                hash_value = line.split(':')[0].strip()  # Extract the hash value only
                if re.fullmatch(r'[a-fA-F0-9]{64}', hash_value):
                    virus_hashes.append(hash_value)
    except Exception as e:
        print(f"Error loading virus database: {e}")
    return virus_hashes

# Save a new hash to the VirusDataBaseHash.bav
def save_hash_to_database(file_path, hash_value):
    try:
        with open(file_path, 'a') as file:
            file.write(f"{hash_value}\n")  # Save hash only
        return True
    except Exception as e:
        print(f"Error saving hash to database: {e}")
        return False

# Calculate the entropy of file data
def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):  # Byte values range from 0 to 255
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

# Main app class
class VirusScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Virus Scanner")
        self.geometry("900x700")
        self.config(bg="#f5f5f5")  # Light background color

        # Initialize queues for file and result processing
        self.file_queue = queue.Queue()
        self.results_queue = queue.Queue()

        # Load virus database
        self.virus_database = load_virus_database(virus_database_file_path)

        self.scanning = False
        self.virus_detected = False  # Flag to indicate virus detection

        # UI Setup
        self.setup_ui()

    def setup_ui(self):
        # Header Label
        header_label = tk.Label(self, text="Advanced Virus Scanner", font=("Arial", 20), bg="#1e90ff", fg="white", pady=10)
        header_label.pack(fill=tk.X)

        # Drive Selection Frame
        drive_frame = tk.Frame(self, bg="#f5f5f5")
        drive_frame.pack(pady=10)
        tk.Label(drive_frame, text="Select Drive or File to Scan:", font=("Arial", 14), bg="#f5f5f5").pack(side=tk.LEFT, padx=5)

        # ComboBox for Drive/File selection
        self.selection_var = tk.StringVar(value="C:/")
        drive_menu = ttk.Combobox(drive_frame, textvariable=self.selection_var, values=["C:/", "D:/", "E:/", "Full System", "Select File"])
        drive_menu.pack(side=tk.LEFT, padx=5)

        # Browse button for selecting a single file
        self.browse_button = tk.Button(self, text="Browse for File", command=self.browse_file, bg="#32cd32", fg="white", font=("Arial", 12))
        self.browse_button.pack(pady=10)

        # Add file hash to the virus database
        self.add_hash_button = tk.Button(self, text="Add File Hash", command=self.add_file_hash, bg="#32cd32", fg="white", font=("Arial", 12))
        self.add_hash_button.pack(pady=20)

        # Start and Stop Buttons
        button_frame = tk.Frame(self, bg="#f5f5f5")
        button_frame.pack(pady=10)
        self.start_button = tk.Button(button_frame, text="Start Scan", command=self.start_scanning, bg="#32cd32", fg="white", font=("Arial", 12))
        self.start_button.pack(side=tk.LEFT, padx=10)
        self.stop_button = tk.Button(button_frame, text="Stop Scan", command=self.stop_scanning, bg="#ff4500", fg="white", font=("Arial", 12), state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10)

        # Refresh Button
        self.refresh_button = tk.Button(self, text="Refresh", command=self.refresh, bg="#1e90ff", fg="white", font=("Arial", 12))
        self.refresh_button.pack(pady=10)

        # Results Tabs
        self.tab_control = ttk.Notebook(self)
        self.safe_files_tab = ttk.Frame(self.tab_control)
        self.virus_files_tab = ttk.Frame(self.tab_control)
        self.suspicious_files_tab = ttk.Frame(self.tab_control)  # New tab for suspicious files
        self.tab_control.add(self.safe_files_tab, text="Safe Files")
        self.tab_control.add(self.virus_files_tab, text="Virus Files")
        self.tab_control.add(self.suspicious_files_tab, text="Suspicious Files")  # Add the new tab
        self.tab_control.pack(expand=1, fill="both", pady=10)

        # Safe Files Listbox
        self.safe_listbox = tk.Listbox(self.safe_files_tab, selectmode=tk.SINGLE, font=("Arial", 10))
        self.safe_listbox.pack(fill="both", expand=True, padx=10, pady=10)

        # Add scrollbar to Safe Files
        safe_scrollbar = ttk.Scrollbar(self.safe_files_tab, orient="vertical", command=self.safe_listbox.yview)
        self.safe_listbox.configure(yscrollcommand=safe_scrollbar.set)
        safe_scrollbar.pack(side="right", fill="y")

        # Virus Files Canvas and Scrollbar
        self.virus_canvas = tk.Canvas(self.virus_files_tab, bg="#f5f5f5")
        self.virus_scrollbar = ttk.Scrollbar(self.virus_files_tab, orient="vertical", command=self.virus_canvas.yview)
        self.virus_canvas.configure(yscrollcommand=self.virus_scrollbar.set)
        self.virus_scrollbar.pack(side="right", fill="y")
        self.virus_canvas.pack(side="left", fill="both", expand=True)

        # Frame inside Virus Canvas
        self.virus_frame = tk.Frame(self.virus_canvas, bg="#f5f5f5")
        self.virus_canvas.create_window((0, 0), window=self.virus_frame, anchor='nw')

        # Suspicious Files Canvas and Scrollbar
        self.suspicious_canvas = tk.Canvas(self.suspicious_files_tab, bg="#f5f5f5")
        self.suspicious_scrollbar = ttk.Scrollbar(self.suspicious_files_tab, orient="vertical", command=self.suspicious_canvas.yview)
        self.suspicious_canvas.configure(yscrollcommand=self.suspicious_scrollbar.set)
        self.suspicious_scrollbar.pack(side="right", fill="y")
        self.suspicious_canvas.pack(side="left", fill="both", expand=True)

        # Frame inside Canvas for Suspicious Files
        self.suspicious_frame = tk.Frame(self.suspicious_canvas, bg="#f5f5f5")
        self.suspicious_canvas.create_window((0, 0), window=self.suspicious_frame, anchor='nw')

        # Progress Bar
        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill=tk.X, pady=10)

        # Text Box for displaying processing logs
        self.processing_text = tk.Text(self, height=10, width=80, bg="#f5f5f5", fg="black", font=("Arial", 10))
        self.processing_text.pack(pady=10)

        self.processing_text.yview(tk.END)  # Auto-scroll when updating
    def browse_file(self):
        """Browse for a single file to add or scan."""
        file_path = filedialog.askopenfilename(title="Select File", filetypes=[("All Files", "*.*")])
        if file_path:
            self.selection_var.set(file_path)  # Update the selection variable with the chosen file path

    def process_files_from_queue(self):
        """Process files from the scanning queue and categorize them."""
        virus_detected = False
        while self.scanning:
            try:
                file_path = self.file_queue.get(timeout=1)
                if file_path == STOP_SIGNAL:
                    break

                try:
                    # Calculate file hash
                    file_hash = self.calculate_file_hash(file_path)

                    # Check if the file is in the virus database
                    if file_hash in self.virus_database:
                        self.add_virus_file(file_path)
                        self.processing_text.insert(tk.END, f"Virus Detected: {file_path}\n")
                        virus_detected = True
                        self.virus_detected = True  # Set the flag to indicate virus detection
                    else:
                        # Check entropy for suspicious files
                        with open(file_path, "rb") as file:
                            data = file.read()
                        entropy = calculate_entropy(data)
                        if entropy > 8:  # High entropy indicates possible obfuscation
                            self.add_suspicious_file(file_path)
                            self.processing_text.insert(tk.END, f"Suspicious File: {file_path}, Entropy: {entropy:.2f}\n")
                        else:
                            self.safe_listbox.insert(tk.END, file_path)
                            self.safe_listbox.yview_moveto(1)  # Auto-scroll to the latest file
                            self.processing_text.insert(tk.END, f"Safe File: {file_path}\n")
                except (PermissionError, OSError) as e:
                    self.processing_text.insert(tk.END, f"Error: {e} - Skipping file: {file_path}\n")
                    continue

                self.processing_text.yview(tk.END)
            except queue.Empty:
                continue

        if virus_detected:
            messagebox.showwarning("Scan Complete", "Virus detected! Check the Virus Files tab.")
        else:
            messagebox.showinfo("Scan Complete", "No virus files detected.")

        self.stop_scanning()

    def calculate_file_hash(self, file_path):
        """Calculate the SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def start_scanning(self):
        """Start the scanning process."""
        self.file_queue = queue.Queue()
        self.safe_listbox.delete(0, tk.END)
        for widget in self.virus_frame.winfo_children():
            widget.destroy()
        for widget in self.suspicious_frame.winfo_children():
            widget.destroy()
        self.processing_text.delete(1.0, tk.END)

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.scanning = True
        self.virus_detected = False  # Reset virus detection flag

        selected_option = self.selection_var.get()
        self.processing_text.insert(tk.END, f"Starting scan for: {selected_option}\n")
        self.processing_text.yview(tk.END)

        if selected_option == "Full System":
            scan_thread = threading.Thread(target=self.scan_directory, args=("Full System",))
        elif selected_option == "Select File":
            file_path = self.selection_var.get()
            scan_thread = threading.Thread(target=self.scan_directory, args=(file_path,))
        else:
            scan_thread = threading.Thread(target=self.scan_directory, args=(selected_option,))

        scan_thread.start()
        worker_thread = threading.Thread(target=self.process_files_from_queue)
        worker_thread.start()

    def scan_directory(self, directory_path):
        """Scan the selected directory for files."""
        if directory_path == "Full System":
            drives = [f"{chr(x)}:/" for x in range(65, 91) if os.path.exists(f"{chr(x)}:/")]
            for drive in drives:
                self.enqueue_files(drive)
        else:
            self.enqueue_files(directory_path)
        self.file_queue.put(STOP_SIGNAL)

    def enqueue_files(self, directory):
        """Add files to the scanning queue."""
        if os.path.isfile(directory):
            self.file_queue.put(directory)
        else:
            for root, _, files in os.walk(directory):
                if not self.scanning:
                    break
                for file in files:
                    file_path = os.path.join(root, file)
                    self.file_queue.put(file_path)

    def stop_scanning(self):
        """Stop the scanning process."""
        self.scanning = False
        self.file_queue.put(STOP_SIGNAL)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if not self.virus_detected:
            messagebox.showinfo("Scan Stopped", "No virus files detected so far.")
        self.processing_text.insert(tk.END, "Scan stopped by user.\n")
        self.processing_text.yview(tk.END)

    def add_file_hash(self):
        """Add a file hash to the virus database."""
        file_path = filedialog.askopenfilename(title="Select File", filetypes=[("All Files", "*.*")])
        if file_path:
            try:
                file_hash = self.calculate_file_hash(file_path)
                if save_hash_to_database(virus_database_file_path, file_hash):
                    messagebox.showinfo("Success", f"Hash for {file_path} saved successfully!")
                    self.processing_text.insert(tk.END, f"Hash saved for {file_path}: {file_hash}\n")
                else:
                    messagebox.showerror("Error", "Failed to save the hash.")
            except Exception as e:
                messagebox.showerror("Error", f"Error calculating hash: {e}")

    def refresh(self):
        """Refresh the UI and reset all fields."""
        self.safe_listbox.delete(0, tk.END)
        for widget in self.virus_frame.winfo_children():
            widget.destroy()
        for widget in self.suspicious_frame.winfo_children():
            widget.destroy()
        self.processing_text.delete(1.0, tk.END)
        
        # Reload the virus database
        self.virus_database = load_virus_database(virus_database_file_path)
        self.processing_text.insert(tk.END, "Virus database refreshed successfully.\n")
        self.processing_text.yview(tk.END)


    def add_virus_file(self, file_path):
        """Add a file to the Virus Files tab."""
        frame = tk.Frame(self.virus_frame, bg="#f5f5f5")
        frame.pack(fill='x', padx=5, pady=5)
        label = tk.Label(frame, text=file_path, anchor='w', bg="#f5f5f5", font=("Arial", 10))
        label.pack(side='left', fill='x', expand=True)
        delete_button = tk.Button(frame, text='DELETE', bg='#ff4500', fg='white', command=lambda: self.delete_virus_file(file_path, frame), font=("Arial", 10))
        delete_button.pack(side='right')

    def delete_virus_file(self, file_path, frame):
        """Delete a virus file."""
        confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete this file?\n{file_path}")
        if confirm:
            try:
                os.remove(file_path)
                frame.destroy()
                messagebox.showinfo("File Deleted", f"File deleted successfully:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while deleting the file:\n{e}")

    def add_suspicious_file(self, file_path):
        """Add a file to the Suspicious Files tab."""
        frame = tk.Frame(self.suspicious_frame, bg="#f5f5f5")
        frame.pack(fill='x', padx=5, pady=5)
        label = tk.Label(frame, text=file_path, anchor='w', bg="#f5f5f5", font=("Arial", 10))
        label.pack(side='left', fill='x', expand=True)
        delete_button = tk.Button(frame, text='DELETE', bg='#ff4500', fg='white', command=lambda: self.delete_suspicious_file(file_path, frame), font=("Arial", 10))
        delete_button.pack(side='right')

    def delete_suspicious_file(self, file_path, frame):
        """Delete a suspicious file."""
        confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete this file?\n{file_path}")
        if confirm:
            try:
                os.remove(file_path)
                frame.destroy()
                messagebox.showinfo("File Deleted", f"File deleted successfully:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while deleting the file:\n{e}")

if __name__ == "__main__":
    
    app = VirusScannerApp()
    app.mainloop()
