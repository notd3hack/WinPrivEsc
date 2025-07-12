
import os
import sys
import json
import webbrowser
import requests
from tkinter import Tk, filedialog, messagebox
import subprocess
from PIL import Image, ImageTk, ImageOps
import tkinter as tk
from tkinter import ttk
import tempfile
import threading
from tkinter import font as tkfont
import sv_ttk
from pillow_heif import register_heif_opener
import hashlib
import imagehash
import pyperclip
import base64

# Developed By Elmir 'd3ploit' Karimli 
# https://www.linkedin.com/in/elmir-karimli-0b2558254/

register_heif_opener()

class AdvancedOSINTViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("dartEXIF Advanced OSINT tool for Image Geolocation")
        self.root.geometry("1800x1000")
        
        sv_ttk.set_theme("dark")
        
        self.current_file = None
        self.gps_coords = None
        self.preview_image = None
        self.preview_photo = None
        
        if not self.check_exiftool():
            messagebox.showerror("Error", "exiftool is not installed")
            sys.exit(1)

        self.setup_ui()

    def check_exiftool(self):
        try:
            subprocess.run(["exiftool", "-ver"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except:
            return False

    def setup_ui(self):
        self.main_panel = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_panel.pack(fill=tk.BOTH, expand=True)

        self.left_panel = ttk.Frame(self.main_panel, width=400)
        self.main_panel.add(self.left_panel, weight=1)

        self.file_frame = ttk.LabelFrame(self.left_panel, text="Files")
        self.file_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.file_listbox = tk.Listbox(
            self.file_frame,
            selectmode=tk.SINGLE,
            bg="#3a3a3a",
            fg="white",
            font=('Helvetica', 10),
            selectbackground="#4a90d9"
        )
        self.file_listbox.pack(fill=tk.BOTH, expand=True)
        self.file_listbox.bind('<<ListboxSelect>>', self.on_file_select)

        self.browse_button = ttk.Button(
            self.file_frame,
            text="Browse Files",
            command=self.browse_files
        )
        self.browse_button.pack(pady=5)

        self.preview_frame = ttk.LabelFrame(self.left_panel, text="Preview")
        self.preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.preview_canvas = tk.Canvas(
            self.preview_frame,
            bg="#2d2d2d",
            highlightthickness=0
        )
        self.preview_canvas.pack(fill=tk.BOTH, expand=True)
        
        self.preview_text = self.preview_canvas.create_text(
            200, 100,
            text="No image selected",
            fill="#aaaaaa",
            font=('Helvetica', 12),
            anchor=tk.CENTER
        )

        self.right_panel = ttk.Frame(self.main_panel)
        self.main_panel.add(self.right_panel, weight=3)

        self.exif_frame = ttk.LabelFrame(self.right_panel, text="EXIF Data")
        self.exif_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.exif_tree = ttk.Treeview(self.exif_frame, columns=('value',))
        self.exif_tree.heading('#0', text='Property')
        self.exif_tree.heading('value', text='Value')

        self.tree_menu = tk.Menu(self.root, tearoff=0)
        self.tree_menu.add_command(label="Copy Value", command=self.copy_tree_value)
        self.tree_menu.add_command(label="Copy All", command=self.copy_all_exif)
        
        self.exif_tree.bind("<Button-3>", self.show_tree_menu)

        self.scrollbar = ttk.Scrollbar(self.exif_frame, orient=tk.VERTICAL, command=self.exif_tree.yview)
        self.exif_tree.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.exif_tree.pack(fill=tk.BOTH, expand=True)

        self.exif_tree.tag_configure('camera', foreground='#4fc3f7')
        self.exif_tree.tag_configure('gps', foreground='#81c784')
        self.exif_tree.tag_configure('image', foreground='#ff8a65')
        self.exif_tree.tag_configure('date', foreground='#ba68c8')
        self.exif_tree.tag_configure('device', foreground='#fff176')
        self.exif_tree.tag_configure('exposure', foreground='#a5d6a7')

        self.osint_frame = ttk.LabelFrame(self.right_panel, text="OSINT Tools")
        self.osint_frame.pack(fill=tk.X, padx=10, pady=5)

        self.metadata_button = ttk.Button(
            self.osint_frame,
            text="View Full Metadata",
            command=self.view_full_metadata,
            state=tk.DISABLED
        )
        self.metadata_button.pack(side=tk.LEFT, padx=5)

        self.reverse_search_button = ttk.Button(
            self.osint_frame,
            text="Reverse Image Search",
            command=self.open_reverse_search,
            state=tk.DISABLED
        )
        self.reverse_search_button.pack(side=tk.LEFT, padx=5)

        self.hash_button = ttk.Button(
            self.osint_frame,
            text="Generate All Hashes",
            command=self.generate_all_hashes,
            state=tk.DISABLED
        )
        self.hash_button.pack(side=tk.LEFT, padx=5)

        self.map_button = ttk.Button(
            self.osint_frame,
            text="Show in Google Maps",
            command=self.show_in_google_maps,
            state=tk.DISABLED
        )
        self.map_button.pack(side=tk.LEFT, padx=5)

        self.toolbar_frame = ttk.Frame(self.right_panel)
        self.toolbar_frame.pack(fill=tk.X, padx=10, pady=5)

        self.expand_button = ttk.Button(
            self.toolbar_frame,
            text="Expand All",
            command=lambda: self.toggle_tree_items(expand=True)
        )
        self.expand_button.pack(side=tk.LEFT, padx=5)

        self.collapse_button = ttk.Button(
            self.toolbar_frame,
            text="Collapse All",
            command=lambda: self.toggle_tree_items(expand=False)
        )
        self.collapse_button.pack(side=tk.LEFT, padx=5)

        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            font=('Helvetica', 9)
        )
        self.status_bar.pack(fill=tk.X)

        self.preview_canvas.bind("<Configure>", self.resize_preview)

    def show_tree_menu(self, event):
        item = self.exif_tree.identify_row(event.y)
        if item:
            self.exif_tree.selection_set(item)
            self.tree_menu.post(event.x_root, event.y_root)

    def copy_tree_value(self):
        selected = self.exif_tree.selection()
        if selected:
            value = self.exif_tree.item(selected[0], 'values')[0]
            pyperclip.copy(value)
            self.status_var.set("Value copied to clipboard")

    def copy_all_exif(self):
        try:
            if not self.current_file:
                messagebox.showwarning("Warning", "No file selected")
                return

            result = subprocess.run(
                ["exiftool", "-a", "-u", "-n", self.current_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            
            pyperclip.copy(result.stdout)
            self.status_var.set("All EXIF data copied to clipboard")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy EXIF data: {str(e)}")

    def resize_preview(self, event=None):
        if self.preview_image:
            self.display_preview(self.preview_image)

    def toggle_tree_items(self, expand=True):
        for item in self.exif_tree.get_children():
            self.exif_tree.item(item, open=expand)

    def browse_files(self):
        files = filedialog.askopenfilenames(
            title="Select files",
            filetypes=[("All files", "*.*")]
        )
        
        if files:
            self.file_listbox.delete(0, tk.END)
            for f in files:
                self.file_listbox.insert(tk.END, f)

    def on_file_select(self, event):
        if not self.file_listbox.curselection():
            return
            
        selected_file = self.file_listbox.get(self.file_listbox.curselection())
        self.current_file = selected_file
        self.status_var.set(f"Processing: {os.path.basename(selected_file)}")
        
        self.create_preview(selected_file)
        threading.Thread(target=self.get_exif_data, args=(selected_file,), daemon=True).start()

    def create_preview(self, image_path):
        try:
            img = Image.open(image_path)
            self.display_preview(img)
            self.enable_osint_buttons()
        except Exception as e:
            self.preview_canvas.delete("preview")
            self.preview_canvas.itemconfig(
                self.preview_text,
                text=f"Cannot display preview\n{str(e)}"
            )
            self.preview_image = None
            self.preview_photo = None
            self.disable_osint_buttons()

    def enable_osint_buttons(self):
        self.metadata_button.config(state=tk.NORMAL)
        self.reverse_search_button.config(state=tk.NORMAL)
        self.hash_button.config(state=tk.NORMAL)
        self.map_button.config(state=tk.NORMAL)

    def disable_osint_buttons(self):
        self.metadata_button.config(state=tk.DISABLED)
        self.reverse_search_button.config(state=tk.DISABLED)
        self.hash_button.config(state=tk.DISABLED)
        self.map_button.config(state=tk.DISABLED)

    def display_preview(self, img):
        self.preview_canvas.delete("preview")
        self.preview_canvas.itemconfig(self.preview_text, text="")
        
        canvas_width = self.preview_canvas.winfo_width()
        canvas_height = self.preview_canvas.winfo_height()
        
        if canvas_width <= 1 or canvas_height <= 1:
            canvas_width = 400
            canvas_height = 400
        
        img_ratio = img.width / img.height
        canvas_ratio = canvas_width / canvas_height
        
        if img_ratio > canvas_ratio:
            new_width = canvas_width
            new_height = int(canvas_width / img_ratio)
        else:
            new_height = canvas_height
            new_width = int(canvas_height * img_ratio)
        
        img = img.resize((new_width, new_height), Image.LANCZOS)
        self.preview_image = img
        self.preview_photo = ImageTk.PhotoImage(img)
        
        x = canvas_width // 2
        y = canvas_height // 2
        
        self.preview_canvas.create_image(
            x, y,
            image=self.preview_photo,
            tags="preview",
            anchor=tk.CENTER
        )

    def get_exif_data(self, image_path):
        try:
            result = subprocess.run(
                ["exiftool", "-j", "-G", "-a", "-u", "-n", image_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            
            exif_data = json.loads(result.stdout)[0]
            
            self.exif_tree.delete(*self.exif_tree.get_children())
            
            self.gps_coords = None
            gps_lat = exif_data.get("GPS:GPSLatitude") or exif_data.get("EXIF:GPSLatitude")
            gps_lon = exif_data.get("GPS:GPSLongitude") or exif_data.get("EXIF:GPSLongitude")
            
            if gps_lat and gps_lon:
                self.gps_coords = (gps_lat, gps_lon)
                self.map_button.config(state=tk.NORMAL)
            else:
                self.map_button.config(state=tk.DISABLED)
            
            categories = {
                'Camera': {
                    'fields': ['Make', 'Model', 'Lens', 'SerialNumber', 'LensID', 'LensModel'],
                    'tag': 'camera'
                },
                'Image': {
                    'fields': ['ImageWidth', 'ImageHeight', 'Resolution', 'Orientation', 'AspectRatio'],
                    'tag': 'image'
                },
                'Date/Time': {
                    'fields': ['DateTimeOriginal', 'CreateDate', 'ModifyDate', 'FileAccessDate'],
                    'tag': 'date'
                },
                'GPS': {
                    'fields': ['GPSLatitude', 'GPSLongitude', 'GPSAltitude', 'GPSSpeed'],
                    'tag': 'gps'
                },
                'Exposure': {
                    'fields': ['ExposureTime', 'FNumber', 'ISO', 'ExposureCompensation', 'Flash'],
                    'tag': 'exposure'
                },
                'Device': {
                    'fields': ['Software', 'Firmware', 'CameraSerialNumber', 'InternalSerialNumber'],
                    'tag': 'device'
                }
            }
            
            parents = {}
            for category in categories:
                parents[category] = self.exif_tree.insert("", tk.END, text=category, open=True)
            
            for group in exif_data:
                if group == "SourceFile":
                    continue
                    
                value = str(exif_data[group])
                name = group.split(':')[-1]
                tag = None
                parent = ""
                
                for category, info in categories.items():
                    if name in info['fields']:
                        parent = parents[category]
                        tag = info['tag']
                        break
                
                if not parent:
                    parts = group.split(':')
                    current_parent = ""
                    
                    for part in parts[:-1]:
                        existing = None
                        for child in self.exif_tree.get_children(current_parent):
                            if self.exif_tree.item(child)['text'] == part:
                                existing = child
                                break
                        
                        if not existing:
                            existing = self.exif_tree.insert(
                                current_parent, tk.END, 
                                text=part, 
                                open=False
                            )
                        current_parent = existing
                    
                    parent = current_parent
                
                self.exif_tree.insert(
                    parent, tk.END, 
                    text=name, 
                    values=(value,),
                    tags=(tag,) if tag else ()
                )
            
            self.status_var.set(f"Ready: {os.path.basename(image_path)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get EXIF data: {str(e)}")
            self.status_var.set("Error occurred")

    def show_in_google_maps(self):
        if not self.gps_coords:
            messagebox.showwarning("Warning", "No GPS coordinates found")
            return
            
        lat, lon = self.gps_coords
        url = f"https://www.google.com/maps?q={lat},{lon}"
        webbrowser.open_new_tab(url)

    def view_full_metadata(self):
        if not self.current_file:
            return
            
        try:
            result = subprocess.run(
                ["exiftool", self.current_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            
            top = tk.Toplevel(self.root)
            top.title("Full Metadata")
            top.geometry("800x600")
            
            text = tk.Text(top, wrap=tk.WORD)
            scroll = ttk.Scrollbar(top, command=text.yview)
            text.configure(yscrollcommand=scroll.set)
            
            scroll.pack(side=tk.RIGHT, fill=tk.Y)
            text.pack(fill=tk.BOTH, expand=True)
            
            text.insert(tk.END, result.stdout)
            text.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get metadata: {str(e)}")

    def open_reverse_search(self):
        if not self.current_file:
            return
            
        try:
            temp_dir = tempfile.gettempdir()
            temp_file = os.path.join(temp_dir, "reverse_search.jpg")
            self.preview_image.save(temp_file, "JPEG")
            
            webbrowser.open(f"https://www.google.com/searchbyimage?image_url=file://{temp_file}")
            webbrowser.open_new_tab(f"https://yandex.com/images/search?rpt=imageview&url={image_url}")
            webbrowser.open_new_tab(f"https://www.bing.com/images/search?q=imgurl:{temp_file}")
            
            self.status_var.set(f"Temp image created at: {temp_file}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open reverse search: {str(e)}")

    def generate_all_hashes(self):
        if not self.current_file:
            return
            
        try:
            with open(self.current_file, 'rb') as f:
                file_data = f.read()
                img = Image.open(self.current_file)
                
                md5 = hashlib.md5(file_data).hexdigest()
                sha1 = hashlib.sha1(file_data).hexdigest()
                sha256 = hashlib.sha256(file_data).hexdigest()
                sha512 = hashlib.sha512(file_data).hexdigest()
                blake2b = hashlib.blake2b(file_data).hexdigest()
                
                phash = str(imagehash.phash(img))
                ahash = str(imagehash.average_hash(img))
                dhash = str(imagehash.dhash(img))
                whash = str(imagehash.whash(img))
                
                hash_window = tk.Toplevel(self.root)
                hash_window.title("Image Hashes")
                hash_window.geometry("900x700")
                
                notebook = ttk.Notebook(hash_window)
                notebook.pack(fill=tk.BOTH, expand=True)
                
                crypto_frame = ttk.Frame(notebook)
                notebook.add(crypto_frame, text="Cryptographic Hashes")
                
                hash_labels = [
                    ("MD5", md5),
                    ("SHA1", sha1),
                    ("SHA256", sha256),
                    ("SHA512", sha512),
                    ("BLAKE2b", blake2b)
                ]
                
                for i, (label, value) in enumerate(hash_labels):
                    frame = ttk.Frame(crypto_frame)
                    frame.pack(fill=tk.X, padx=5, pady=2)
                    
                    ttk.Label(frame, text=f"{label}:", width=10).pack(side=tk.LEFT)
                    entry = ttk.Entry(frame, width=100)
                    entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
                    entry.insert(0, value)
                    entry.bind("<1>", lambda e, v=value: self.copy_to_clipboard(v))
                    
                    ttk.Button(
                        frame, 
                        text="Copy", 
                        command=lambda v=value: self.copy_to_clipboard(v)
                    ).pack(side=tk.RIGHT)
                
                img_frame = ttk.Frame(notebook)
                notebook.add(img_frame, text="Image Hashes")
                
                img_hash_labels = [
                    ("Perceptual Hash", phash),
                    ("Average Hash", ahash),
                    ("Difference Hash", dhash),
                    ("Wavelet Hash", whash)
                ]
                
                for i, (label, value) in enumerate(img_hash_labels):
                    frame = ttk.Frame(img_frame)
                    frame.pack(fill=tk.X, padx=5, pady=2)
                    
                    ttk.Label(frame, text=f"{label}:", width=15).pack(side=tk.LEFT)
                    entry = ttk.Entry(frame, width=100)
                    entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
                    entry.insert(0, value)
                    entry.bind("<1>", lambda e, v=value: self.copy_to_clipboard(v))
                    
                    ttk.Button(
                        frame, 
                        text="Copy", 
                        command=lambda v=value: self.copy_to_clipboard(v)
                    ).pack(side=tk.RIGHT)
                
                b64_frame = ttk.Frame(notebook)
                notebook.add(b64_frame, text="Base64")
                
                base64_str = base64.b64encode(file_data).decode('utf-8')
                short_b64 = base64_str[:100] + "..." if len(base64_str) > 100 else base64_str
                
                ttk.Label(b64_frame, text="Base64 (first 100 chars):").pack(anchor='w')
                b64_entry = tk.Text(b64_frame, height=5, wrap=tk.WORD)
                b64_entry.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                b64_entry.insert(tk.END, short_b64)
                
                ttk.Button(
                    b64_frame,
                    text="Copy Full Base64",
                    command=lambda: self.copy_to_clipboard(base64_str)
                ).pack(pady=5)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate hashes: {str(e)}")

    def copy_to_clipboard(self, text):
        pyperclip.copy(text)
        self.status_var.set("Copied to clipboard")

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedOSINTViewer(root)
    root.mainloop()
