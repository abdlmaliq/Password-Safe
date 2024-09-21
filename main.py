from tkinter import *
from tkinter import messagebox
import random
import pyperclip
import json

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os



# ---------------------------- PASSWORD GENERATOR ------------------------------- #

def generate():
    pass_text.delete(0, END)
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
               'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
               'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    nr_letters = random.randint(8, 10)
    nr_symbols = random.randint(2, 4)
    nr_numbers = random.randint(2, 4)

    password_list = [random.choice(letters) for char in range(nr_letters)]
    password_list += [random.choice(symbols) for char in range(nr_symbols)]
    password_list += [random.choice(numbers) for char in range(nr_numbers)]

    random.shuffle(password_list)

    password = "".join(password_list)

    # password = ""
    # for char in password_list:
    #   password += char

    pass_text.insert(0, password)
    pyperclip.copy(pass_text.get())

    # ------Encrypt Password-------#

def generate_key(password: str, salt: bytes = None) -> bytes:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_string(string: str, key: bytes) -> str:
    f = Fernet(key)
    return f.encrypt(string.encode()).decode()

def decrypt_string(encrypted_string: str, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(encrypted_string.encode()).decode()


# ---------------------------- SAVE PASSWORD ------------------------------- #

# ---------------------------- UI SETUP ------------------------------- #


window = Tk()
window.title("Password Safe")
window.config(padx=20, pady=20)

canvas = Canvas(width=200, height=200)
photo_img = PhotoImage(file="logo.png")
canvas.create_image(100, 100, image=photo_img)
canvas.grid(column=1, row=0)


def add_values():
    site = website_text.get()
    user = user_text.get()
    passw = pass_text.get()

    if len(site) < 1 or len(user) < 1 or len(passw) < 1:
        messagebox.showinfo(title="Alert", message="No box should be empty")
    else:
        is_ok = messagebox.askokcancel(title=site, message=f"Are you sure you want to save this info? \n "
                                                           f"Email: {user}\n Password: {passw}")

        if is_ok:
            try:
                with open("data.json", mode="r") as data:
                    json_data = json.load(data)
            except FileNotFoundError:
                json_data = {}

            # Encrypt the data
            master_password = "your_master_password_here"  # You should get this securely from the user
            key, salt = generate_key(master_password)

            new_entry = {
                "username": encrypt_string(user, key),
                "password": encrypt_string(passw, key)
            }

            json_data[site] = new_entry
            json_data['salt'] = base64.b64encode(salt).decode()

            with open("data.json", mode="w") as data:
                json.dump(json_data, data, indent=4)

            website_text.delete(0, END)
            user_text.delete(0, END)
            pass_text.delete(0, END)

            # Encrypt the data
            master_password = "your_master_password_here"  # You should get this securely from the user
            key, salt = generate_key(master_password)

            new_entry = {
                "username": encrypt_string(user, key),
                "password": encrypt_string(passw, key)
            }

            json_data[site] = new_entry
            json_data['salt'] = base64.b64encode(salt).decode()

            with open("data.json", mode="w") as data:
                json.dump(json_data, data, indent=4)

            website_text.delete(0, END)
            user_text.delete(0, END)
            pass_text.delete(0, END)


# Modify your search_site function
def search_site():
    site1 = website_text.get()
    try:
        with open("data.json", "r") as data:
            json_data = json.load(data)

        if site1 in json_data:
            master_password = "your_master_password_here"  # You should get this securely from the user
            salt = base64.b64decode(json_data['salt'])
            key, _ = generate_key(master_password, salt)

            username = decrypt_string(json_data[site1]["username"], key)
            password = decrypt_string(json_data[site1]["password"], key)

            messagebox.showinfo(title=f"Details for {site1}", message=f"Username: {username}\n"
                                                                      f"Password: {password}")
        else:
            messagebox.showinfo(title="Alert", message="No such record in the database")
    except FileNotFoundError:
        messagebox.showinfo(title="Alert", message="No data file found")
    except Exception as e:
        messagebox.showerror(title="Error", message=f"An error occurred: {str(e)}")


website_label = Label(text="Website: ", )
website_label.grid(column=0, row=1)

user_label = Label(text="Email/Username: ")
user_label.grid(column=0, row=2)

pass_label = Label(text="Password: ", )
pass_label.grid(column=0, row=3, )

website_text = Entry(width=35)
website_text.focus()
website_text.grid(column=1, row=1, columnspan=2)

user_text = Entry(width=35)
user_text.grid(row=2, column=1, columnspan=2)

pass_text = Entry(width=17)
pass_text.grid(row=3, column=1)

gen_but = Button(text="Generate Password", command=generate)
gen_but.grid(row=3, column=2)

add_but = Button(text="Add", width=30, command=add_values)
add_but.grid(row=4, column=1, columnspan=2)

search_but = Button(text="Search", command=search_site)
search_but.grid(row=1, column=2)

window.mainloop()