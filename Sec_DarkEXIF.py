https://www.linkedin.com/in/elmir-karimli-0b2558254/

import os
import sys
import json
import webbrowser
from tkinter import Tk, filedialog, messagebox
import subprocess
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import ttk
import folium
import tempfile
import threading
from tkinter import font as tkfont


# Developed By Elmir 'd3ploit' Karimli 
# https://www.linkedin.com/in/elmir-karimli-0b2558254/


class DarkThemeEXIFViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("Dark EXIF Analyzer v2.1")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        self.bg_color = "#2d2d2d"
        self.fg_color = "#e0e0e0"
        self.accent_color = "#3a7ebf"
        self.highlight_color = "#4a90d9"
        self.tree_bg = "#3a3a3a"
        self.tree_fg = "#ffffff"
        self.tree_highlight = "#4a4a4a"
        
        self.root.configure(bg=self.bg_color)
        
        if not self.check_exiftool():
            messagebox.showerror("Error", "EXIFTool is not installed. Please install EXIFTool first.")
            sys.exit(1)
        
        self.setup_fonts()
        self.setup_ui()
        self.setup_menu()
        
    def setup_fonts(self):
        self.default_font = tkfont.nametofont("TkDefaultFont")
        self.default_font.configure(size=10)
        
        self.bold_font = tkfont.Font(
            family=self.default_font.cget("family"),
            size=self.default_font.cget("size"),
            weight="bold"
        )
        
        self.tree_font = tkfont.Font(
            family="Consolas",
            size=10
        )
    
    def check_exiftool(self):
        try:
            subprocess.run(["exiftool", "-ver"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except:
            return False
    
    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('.', 
                       background=self.bg_color,
                       foreground=self.fg_color,
                       font=self.default_font)
        
        style.configure("Treeview",
                       background=self.tree_bg,
                       foreground=self.tree_fg,
                       fieldbackground=self.tree_bg,
                       font=self.tree_font)
        
        style.map('Treeview', 
                 background=[('selected', self.highlight_color)],
                 foreground=[('selected', 'white')])
        
        style.configure('TButton',
                       background=self.accent_color,
                       foreground='white',
                       borderwidth=1,
                       focusthickness=3,
                       focuscolor='none')
        
        style.map('TButton',
                 background=[('active', self.highlight_color),
                            ('disabled', '#5a5a5a')])
        
        style.configure('TLabelframe',
                       background=self.bg_color,
                       foreground=self.fg_color)
        
        style.configure('TLabelframe.Label',
                       background=self.bg_color,
                       foreground=self.accent_color)
        
        style.configure('Vertical.TScrollbar',
                       background=self.bg_color,
                       troughcolor=self.bg_color,
                       arrowcolor=self.fg_color)
        
        self.main_panel = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_panel.pack(fill=tk.BOTH, expand=True)
        
        self.left_panel = ttk.Frame(self.main_panel, width=350)
        self.main_panel.add(self.left_panel, weight=1)
        
        self.file_frame = ttk.LabelFrame(self.left_panel, text="📁 File Selection")
        self.file_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.file_listbox = tk.Listbox(
            self.file_frame,
            selectmode=tk.SINGLE,
            bg=self.tree_bg,
            fg=self.tree_fg,
            selectbackground=self.highlight_color,
            selectforeground='white',
            font=self.default_font
        )
        self.file_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.file_listbox.bind('<<ListboxSelect>>', self.on_file_select)
        
        self.browse_button = ttk.Button(
            self.file_frame,
            text="🔍 Browse Files...",
            command=self.browse_files
        )
        self.browse_button.pack(pady=5)
        
        self.preview_frame = ttk.LabelFrame(self.left_panel, text="🖼️ Preview")
        self.preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.preview_label = tk.Label(
            self.preview_frame,
            bg=self.bg_color
        )
        self.preview_label.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.right_panel = ttk.Frame(self.main_panel)
        self.main_panel.add(self.right_panel, weight=3)
        
        self.exif_frame = ttk.LabelFrame(self.right_panel, text="📊 EXIF Data")
        self.exif_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.exif_tree = ttk.Treeview(
            self.exif_frame,
            columns=('value', 'category'),
            selectmode='extended',
            style='Treeview'
        )
        
        self.exif_tree.heading('#0', text='Property', anchor=tk.W)
        self.exif_tree.heading('value', text='Value', anchor=tk.W)
        self.exif_tree.heading('category', text='Category', anchor=tk.W)
        
        self.exif_tree.column('#0', width=300, stretch=tk.YES)
        self.exif_tree.column('value', width=500, stretch=tk.YES)
        self.exif_tree.column('category', width=150, stretch=tk.YES)
        
        self.scrollbar = ttk.Scrollbar(
            self.exif_frame,
            orient=tk.VERTICAL,
            command=self.exif_tree.yview
        )
        self.exif_tree.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.exif_tree.pack(fill=tk.BOTH, expand=True)
        
        self.exif_tree.tag_configure('important', foreground='#ffcc00')
        self.exif_tree.tag_configure('gps', foreground='#4caf50')
        self.exif_tree.tag_configure('camera', foreground='#f44336')
        self.exif_tree.tag_configure('date', foreground='#9c27b0')
        self.exif_tree.tag_configure('size', foreground='#2196f3')
        
        self.button_frame = ttk.Frame(self.right_panel)
        self.button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.map_button = ttk.Button(
            self.button_frame,
            text="🗺️ Show in Google Maps",
            command=self.show_in_google_maps,
            state=tk.DISABLED
        )
        self.map_button.pack(side=tk.LEFT, padx=5)
        
        self.expand_button = ttk.Button(
            self.button_frame,
            text="➕ Expand All",
            command=lambda: self.toggle_tree_items(expand=True)
        )
        self.expand_button.pack(side=tk.LEFT, padx=5)
        
        self.collapse_button = ttk.Button(
            self.button_frame,
            text="➖ Collapse All",
            command=lambda: self.toggle_tree_items(expand=False)
        )
        self.collapse_button.pack(side=tk.LEFT, padx=5)
        
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(fill=tk.X)
        
        self.current_file = None
        self.gps_coords = None
    
    def setup_menu(self):
        menubar = tk.Menu(self.root, bg=self.bg_color, fg=self.fg_color)
        
        file_menu = tk.Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        file_menu.add_command(label="Open File...", command=self.browse_files)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        tools_menu = tk.Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        tools_menu.add_command(label="Show All EXIF Data", command=self.show_all_exif)
        tools_menu.add_command(label="Save EXIF as JSON", command=self.save_exif_as_json)
        tools_menu.add_command(label="Save EXIF as CSV", command=self.save_exif_as_csv)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        view_menu = tk.Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        view_menu.add_command(label="Expand All", command=lambda: self.toggle_tree_items(expand=True))
        view_menu.add_command(label="Collapse All", command=lambda: self.toggle_tree_items(expand=False))
        menubar.add_cascade(label="View", menu=view_menu)
        
        help_menu = tk.Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def toggle_tree_items(self, expand=True):
        """Expand or collapse all tree items"""
        for item in self.exif_tree.get_children():
            self.exif_tree.item(item, open=expand)
            for child in self.exif_tree.get_children(item):
                self.exif_tree.item(child, open=expand)
    
    def browse_files(self):
        filetypes = (
            ('Image files', '*.jpg *.jpeg *.png *.tiff *.webp'),
            ('RAW files', '*.cr2 *.nef *.arw *.dng'),
            ('All files', '*.*')
        )
        
        files = filedialog.askopenfilenames(
            title='Select files',
            initialdir='/',
            filetypes=filetypes
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
        self.status_var.set(f"Processing: {os.path.basename(selected_file)}...")
        self.root.update()
        
        self.create_preview(selected_file)
        
        threading.Thread(target=self.get_exif_data, args=(selected_file,), daemon=True).start()
    
    def create_preview(self, image_path):
        try:
            img = Image.open(image_path)
            img.thumbnail((400, 400))
            photo = ImageTk.PhotoImage(img)
            
            self.preview_label.config(image=photo)
            self.preview_label.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Could not create preview: {str(e)}")
    
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
            gps_lat = exif_data.get("EXIF:GPSLatitude")
            gps_lon = exif_data.get("EXIF:GPSLongitude")
            
            if gps_lat and gps_lon:
                self.gps_coords = (gps_lat, gps_lon)
                self.map_button.config(state=tk.NORMAL)
            else:
                self.map_button.config(state=tk.DISABLED)
            
            categories = {
                'Camera': ['Make', 'Model', 'Lens', 'SerialNumber', 'ISO', 'FocalLength'],
                'Image': ['ImageWidth', 'ImageHeight', 'Orientation', 'XResolution', 'YResolution'],
                'Date': ['DateTimeOriginal', 'CreateDate', 'ModifyDate'],
                'GPS': ['GPSLatitude', 'GPSLongitude', 'GPSAltitude', 'GPSSpeed'],
                'Exposure': ['ExposureTime', 'FNumber', 'ExposureProgram', 'ExposureCompensation'],
                'Advanced': ['ApertureValue', 'ShutterSpeedValue', 'BrightnessValue', 'LightSource']
            }
            
            for group in exif_data:
                if group == "SourceFile":
                    continue
                    
                tag = None
                category = "Other"
                value = str(exif_data[group])
                
                display_name = group.split(':')[-1]
                
                for cat, fields in categories.items():
                    if display_name in fields:
                        category = cat
                        if cat == 'GPS':
                            tag = 'gps'
                        elif cat == 'Camera':
                            tag = 'camera'
                        elif cat == 'Date':
                            tag = 'date'
                        elif cat == 'Image' and ('Width' in display_name or 'Height' in display_name):
                            tag = 'size'
                        break
                
                parent = ""
                group_parts = group.split(':')
                
                for i, part in enumerate(group_parts):
                    if i < len(group_parts)-1:
                        existing = None
                        for child in self.exif_tree.get_children(parent):
                            if self.exif_tree.item(child)['text'] == part:
                                existing = child
                                break
                        
                        if not existing:
                            existing = self.exif_tree.insert(
                                parent, 
                                tk.END, 
                                text=part, 
                                values=("", category),
                                open=True  
                            )
                        parent = existing
                    else:
                        self.exif_tree.insert(
                            parent, 
                            tk.END, 
                            text=display_name, 
                            values=(value, category),
                            tags=(tag,) if tag else ()
                        )
            
            for child in self.exif_tree.get_children():
                self.exif_tree.item(child, open=True)
            
            self.status_var.set(f"Completed: {os.path.basename(image_path)}")
            
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"EXIFTool error:\n{e.stderr}")
            self.status_var.set("Failed to get EXIF data")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error:\n{str(e)}")
            self.status_var.set("Error occurred")
    
    def show_in_google_maps(self):
        if not self.gps_coords:
            messagebox.showwarning("Warning", "No GPS coordinates found in this image.")
            return
            
        lat, lon = self.gps_coords
        url = f"https://www.google.com/maps?q={lat},{lon}"
        
        self.create_interactive_map(lat, lon)
        
        webbrowser.open_new_tab(url)
    
    def create_interactive_map(self, lat, lon):
        """Create interactive map with Folium and open in browser"""
        try:
            m = folium.Map(location=[lat, lon], zoom_start=15)
            
            folium.Marker(
                [lat, lon],
                popup=f"Photo Location<br>Lat: {lat}<br>Lon: {lon}",
                tooltip="Taken here",
                icon=folium.Icon(color="red", icon="camera", prefix="fa")
            ).add_to(m)
            
            temp_dir = tempfile.mkdtemp()
            map_file = os.path.join(temp_dir, "map.html")
            m.save(map_file)
            
            webbrowser.open_new_tab(f"file://{map_file}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create map:\n{str(e)}")
    
    def show_all_exif(self):
        if not self.current_file:
            messagebox.showwarning("Warning", "Please select a file first.")
            return
            
        try:
            result = subprocess.run(
                ["exiftool", "-a", "-u", "-n", self.current_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            
            top = tk.Toplevel(self.root)
            top.title("All EXIF Data")
            top.geometry("900x700")
            top.configure(bg=self.bg_color)
            
            text = tk.Text(
                top,
                wrap=tk.WORD,
                bg=self.tree_bg,
                fg=self.tree_fg,
                insertbackground=self.fg_color,
                selectbackground=self.highlight_color,
                font=self.tree_font
            )
            
            scroll = ttk.Scrollbar(
                top,
                command=text.yview,
                style='Vertical.TScrollbar'
            )
            text.configure(yscrollcommand=scroll.set)
            
            scroll.pack(side=tk.RIGHT, fill=tk.Y)
            text.pack(fill=tk.BOTH, expand=True)
            
            text.insert(tk.END, result.stdout)
            text.config(state=tk.DISABLED)
            
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"EXIFTool error:\n{e.stderr}")
    
    def save_exif_as_json(self):
        if not self.current_file:
            messagebox.showwarning("Warning", "Please select a file first.")
            return
            
        file = filedialog.asksaveasfilename(
            title="Save as JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        
        if file:
            try:
                result = subprocess.run(
                    ["exiftool", "-j", "-a", "-u", "-n", self.current_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
                
                with open(file, 'w') as f:
                    f.write(result.stdout)
                
                messagebox.showinfo("Success", f"EXIF data saved to {file}")
            except Exception as e:
                messagebox.showerror("Error", f"Save failed:\n{str(e)}")
    
    def save_exif_as_csv(self):
        if not self.current_file:
            messagebox.showwarning("Warning", "Please select a file first.")
            return
            
        file = filedialog.asksaveasfilename(
            title="Save as CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        
        if file:
            try:
                result = subprocess.run(
                    ["exiftool", "-csv", "-a", "-u", "-n", self.current_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
                
                with open(file, 'w') as f:
                    f.write(result.stdout)
                
                messagebox.showinfo("Success", f"EXIF data saved to {file}")
            except Exception as e:
                messagebox.showerror("Error", f"Save failed:\n{str(e)}")
    
    def show_about(self):
        about_text = """Dark EXIF Analyzer v2.1

This tool allows you to view detailed EXIF metadata 
from photo and image files with a modern dark interface.

Features:
- Dark theme UI with better readability
- Organized EXIF data by categories
- Color-coded important values
- GPS coordinates with map integration
- Image preview
- Save EXIF data in multiple formats

Developer: AI Assistant
License: MIT
"""
        messagebox.showinfo("About", about_text)

if __name__ == "__main__":
    root = tk.Tk()
    app = DarkThemeEXIFViewer(root)
    root.mainloop()
