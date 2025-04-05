import tkinter as tk
from tkinter import messagebox
import random
import string

# Generate password logic
def generate_password(auto=False):
    try:
        length = int(length_entry.get())
        if length < 4:
            if not auto:
                messagebox.showwarning("Too Short", "Password length must be at least 4.")
            return

        pool = ""
        if lowercase_var.get(): pool += string.ascii_lowercase
        if uppercase_var.get(): pool += string.ascii_uppercase
        if digits_var.get(): pool += string.digits
        if symbols_var.get(): pool += string.punctuation

        if not pool:
            if not auto:
                messagebox.showerror("No character sets selected", "Enable at least one option.")
            return

        password = ''.join(random.choices(pool, k=length))
        result_var.set(password)
        if not show_password.get():
            result_entry.config(show="*")

    except ValueError:
        if not auto:
            messagebox.showerror("Invalid input", "Please enter a valid number.")

def copy_to_clipboard():
    password = result_var.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        show_toast("✅ Copied to clipboard!")

def show_toast(msg):
    toast = tk.Toplevel(root)
    toast.overrideredirect(True)
    toast.configure(bg="#323232")
    toast.geometry(f"200x35+{root.winfo_x() + 120}+{root.winfo_y() + 270}")
    tk.Label(toast, text=msg, bg="#323232", fg="white", font=("Segoe UI", 10, "bold")).pack(expand=True)
    toast.after(1400, toast.destroy)

def toggle_password():
    if show_password.get():
        result_entry.config(show="•")
        toggle_btn.config(text="👁️ Show")
        show_password.set(False)
    else:
        result_entry.config(show="")
        toggle_btn.config(text="🙈 Hide")
        show_password.set(True)

# UI Setup
root = tk.Tk()
root.title("🔐 Pro Password Generator")
root.geometry("500x520")
root.configure(bg="#121212")

# Fonts & Styles
TITLE_FONT = ("Segoe UI", 20, "bold")
LABEL_FONT = ("Segoe UI", 12)
ENTRY_FONT = ("Segoe UI", 11)
BTN_FONT = ("Segoe UI", 11, "bold")
ACCENT_COLOR = "#00bfa6"

# Variables
result_var = tk.StringVar()
uppercase_var = tk.BooleanVar(value=True)
lowercase_var = tk.BooleanVar(value=True)
digits_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=True)
show_password = tk.BooleanVar(value=False)

# --- UI Components ---

# Title
tk.Label(root, text="Smart Password Generator", font=TITLE_FONT, fg="#ffffff", bg="#121212").pack(pady=(20, 10))

# Length
tk.Label(root, text="Password Length", font=LABEL_FONT, bg="#121212", fg="#dddddd").pack()
length_entry = tk.Entry(root, font=ENTRY_FONT, justify="center", width=10, bd=0, relief="flat", bg="#1e1e1e", fg="#ffffff", insertbackground="white")
length_entry.insert(0, "12")
length_entry.pack(pady=5)

# Options Frame
options = tk.Frame(root, bg="#121212")
options.pack(pady=10)

tk.Checkbutton(options, text="Uppercase", variable=uppercase_var, bg="#121212", fg="#dddddd",
               selectcolor="#121212", font=LABEL_FONT, activeforeground=ACCENT_COLOR,
               command=lambda: generate_password(auto=True)).grid(row=0, column=0, padx=10)

tk.Checkbutton(options, text="Numbers", variable=digits_var, bg="#121212", fg="#dddddd",
               selectcolor="#121212", font=LABEL_FONT, activeforeground=ACCENT_COLOR,
               command=lambda: generate_password(auto=True)).grid(row=0, column=1, padx=10)

tk.Checkbutton(options, text="Symbols", variable=symbols_var, bg="#121212", fg="#dddddd",
               selectcolor="#121212", font=LABEL_FONT, activeforeground=ACCENT_COLOR,
               command=lambda: generate_password(auto=True)).grid(row=1, column=0, padx=10, pady=5)

tk.Checkbutton(options, text="Lowercase", variable=lowercase_var, bg="#121212", fg="#dddddd",
               selectcolor="#121212", font=LABEL_FONT, activeforeground=ACCENT_COLOR,
               command=lambda: generate_password(auto=True)).grid(row=1, column=1, padx=10, pady=5)

# Generate Button
generate_btn = tk.Button(
    root, text="🚀 Generate", font=BTN_FONT, bg=ACCENT_COLOR, fg="#121212",
    activebackground="#00a38c", activeforeground="white",
    bd=0, padx=25, pady=10, command=generate_password
)
generate_btn.pack(pady=15)

# Password Result Display
tk.Label(root, text="Generated Password", font=LABEL_FONT, bg="#121212", fg="#dddddd").pack()
pw_frame = tk.Frame(root, bg="#121212")
pw_frame.pack(pady=5)

result_entry = tk.Entry(pw_frame, textvariable=result_var, font=ENTRY_FONT, justify="center", width=28,
                        bd=0, bg="#1e1e1e", fg="#ffffff", insertbackground="white", show="•")
result_entry.pack(side="left", padx=(0, 5))

toggle_btn = tk.Button(pw_frame, text="👁️ Show", font=("Segoe UI", 10), bg="#1e1e1e", fg="#00bfa6",
                       activebackground="#1e1e1e", activeforeground="#00ffd2",
                       bd=0, command=toggle_password)
toggle_btn.pack(side="left")

# Copy Button
tk.Button(root, text="📋 Copy", font=BTN_FONT, bg="#333333", fg="white",
          activebackground="#444444", activeforeground="white",
          bd=0, padx=20, pady=8, command=copy_to_clipboard).pack(pady=10)

# Run App
generate_password(auto=True)
root.mainloop()

