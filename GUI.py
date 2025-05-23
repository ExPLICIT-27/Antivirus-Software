from tkinter import *
from tkinter import filedialog
import subprocess
import ttkbootstrap as tb

root = tb.Window(themename="vapor")

root.title("Antivirus Software (by 23BCE1104, 23BCE1133)")
root.geometry("1440x900")


file_path = ""
upload_type = "file"  

def file_dialog():
    global file_path
    if upload_type == "file":
        file_path = filedialog.askopenfilename()
    else:
        file_path = filedialog.askdirectory()
    if file_path:
        file_label.config(text="Chosen path: " + file_path)
    else:
        file_label.config(text="No path selected")

def execute_engine(file_path):
    if file_path:
        file_label.config(text=file_path)
        result = subprocess.run(["./engine", file_path], stdout=subprocess.PIPE)
        output_text.delete(1.0, END)  
        output_text.insert(END, result.stdout.decode())  
        output_text.see(END)
    else:
        file_label.config(text="No path selected")

def toggle_upload_type():
    global upload_type
    if upload_type == "file":
        upload_type = "directory"
        toggle_button.config(text="Switch to File Upload")
    else:
        upload_type = "file"
        toggle_button.config(text="Switch to Directory Upload")

my_label = tb.Label(text="Enhanced AV Software", font=("Courier New", 40, "bold"), bootstyle="default")
my_label.pack(pady=10)

toggle_button = tb.Button(text="Switch to Directory Upload", bootstyle="secondary", command=toggle_upload_type)
toggle_button.pack(pady=10)

file_label = tb.Label(text="", font=("Helvetica", 12), bootstyle="default")
file_label.pack(pady=10)

image = PhotoImage(file="Images/upload_image.png")

image_button = tb.Label(image=image)
image_button.pack(pady=10)

image_button.bind("<Button-1>", lambda event: file_dialog())

my_button = tb.Button(text="Upload", bootstyle="primary, outline", command=lambda: execute_engine(file_path))
my_button.config(padding="40 15")
my_button.pack(pady=20)

my_label = tb.Label(text="Scan results", font=("Courier New", 30, "bold"), bootstyle="default")
my_label.pack(pady=20)

output_text = Text(root, width=200, height=50, wrap='word', font=("Courier New", 14, "bold"))
output_text.pack(pady=10)


root.mainloop()