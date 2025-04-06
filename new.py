import tkinter as tk
from tkinter import ttk
from ttkthemes import ThemedTk
from PIL import Image, ImageTk

# Splash Screen Class
class SplashScreen:
    def __init__(self, master):
        self.master = master
        self.splash_frame = tk.Frame(self.master, bg="#4B79A1")
        self.splash_frame.pack(fill=tk.BOTH, expand=True)

        # Add a Logo/Image
        logo_image = Image.open("logo.png")  # Replace with your logo/image
        logo_image = logo_image.resize((200, 200))
        self.logo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(self.splash_frame, image=self.logo, bg="#4B79A1")
        logo_label.pack(pady=30)

        # Add Text
        tk.Label(
            self.splash_frame,
            text="Welcome to My Enhanced App",
            font=("Helvetica", 18, "bold"),
            bg="#4B79A1",
            fg="white"
        ).pack(pady=10)

        # Progress Bar
        self.progress = ttk.Progressbar(self.splash_frame, length=300, mode='determinate')
        self.progress.pack(pady=20)
        self.progress_value = 0
        self.animate_progress()

    def animate_progress(self):
        if self.progress_value < 100:
            self.progress_value += 5
            self.progress['value'] = self.progress_value
            self.master.after(100, self.animate_progress)
        else:
            self.splash_frame.destroy()
            App(self.master)  # Transition to Main App

# Main Application Class
class App:
    def __init__(self, master):
        self.master = master
        self.master.title("Enhanced Tkinter Application")
        self.master.geometry("600x400")

        # Create Main Frame
        main_frame = ttk.Frame(self.master, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title Label
        ttk.Label(main_frame, text="Dynamic Tkinter App", font=("Arial", 24)).pack(pady=20)

        # Input Fields
        ttk.Label(main_frame, text="Your Name:").pack(anchor=tk.W, padx=10)
        self.name_entry = ttk.Entry(main_frame, width=40)
        self.name_entry.pack(pady=5)

        ttk.Label(main_frame, text="Your Email:").pack(anchor=tk.W, padx=10)
        self.email_entry = ttk.Entry(main_frame, width=40)
        self.email_entry.pack(pady=5)

        # Button with Hover Effect
        self.submit_button = ttk.Button(main_frame, text="Submit", command=self.on_submit)
        self.submit_button.pack(pady=20)
        self.submit_button.bind("<Enter>", self.on_hover)
        self.submit_button.bind("<Leave>", self.on_leave)

        # Output Label
        self.output_label = ttk.Label(main_frame, text="", font=("Arial", 12))
        self.output_label.pack(pady=10)

    def on_submit(self):
        name = self.name_entry.get()
        email = self.email_entry.get()
        self.output_label.config(text=f"Thank you, {name}! Your email '{email}' is saved.")

    def on_hover(self, event):
        self.submit_button.config(style="Hover.TButton")

    def on_leave(self, event):
        self.submit_button.config(style="TButton")

# Styling with ttk Themes
def set_styles(theme_app):
    style = ttk.Style(theme_app)
    style.configure("TButton", font=("Helvetica", 12), padding=6)
    style.configure("Hover.TButton", background="#4B79A1", foreground="white")

# Main Program
if __name__ == "__main__":
    # Use ThemedTk for pre-built modern themes
    root = ThemedTk(theme="adapta")  # Try different themes like 'arc', 'clam', 'radiance', etc.
    set_styles(root)

    # Show Splash Screen First
    SplashScreen(root)

    root.mainloop()
