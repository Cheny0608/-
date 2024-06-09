import tkinter as tk
from tkinter import messagebox, simpledialog
import string
import random
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

class PasswordManager:
    def __init__(self, key_file="key.bin", storage_file="passwords.dat"):
        self.key_file = key_file
        self.storage_file = storage_file
        self.load_or_create_key()
        self.load_or_create_storage()

    def load_or_create_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as file:
                self.key = file.read()
        else:
            self.key = self.generate_key()
            with open(self.key_file, 'wb') as file:
                file.write(self.key)

    def generate_key(self):
        return os.urandom(32)

    def load_or_create_storage(self):
        self.data = {}
        if os.path.exists(self.storage_file):
            with open(self.storage_file, 'rb') as file:
                data = file.read()
                if data:
                    try:
                        decrypted_data = self.decrypt(data)
                        self.data = json.loads(decrypted_data)
                        if not isinstance(self.data, dict):
                            print("Warning: Decrypted data is not in expected format. Creating new storage.")
                            self.data = {}
                    except Exception as e:
                        print(f"Error decrypting data: {e}")
                        print("Creating new storage.")

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        return ct_bytes, cipher.iv

    def decrypt(self, data):
        iv = data[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)
        return pt.decode()

    def save_storage(self):
        encrypted_data, iv = self.encrypt(json.dumps(self.data))
        with open(self.storage_file, 'wb') as file:
            file.write(iv + encrypted_data)

    def add_account(self, account_name, username, password):
        self.data[account_name] = {"username": username, "password": password}
        self.save_storage()

    def get_account(self, account_name):
        return self.data.get(account_name, {})

    def update_account(self, account_name, username, password):
        if account_name in self.data:
            self.data[account_name] = {"username": username, "password": password}
            self.save_storage()
        else:
            messagebox.showerror("Error", f"Account '{account_name}' does not exist.")

    def delete_account(self, account_name):
        if account_name in self.data:
            del self.data[account_name]
            self.save_storage()
        else:
            messagebox.showerror("Error", f"Account '{account_name}' does not exist.")

    def list_accounts(self):
        accounts = ""
        for account_name in self.data:
            accounts += f"{account_name}: {self.data[account_name]['username']}\n"
        return accounts

    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

class PasswordManagerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")

        self.password_manager = PasswordManager()

        self.add_button = tk.Button(master, text="Add Account", command=self.add_account_window)
        self.add_button.pack()

        self.update_button = tk.Button(master, text="Update Account", command=self.update_account_window)
        self.update_button.pack()

        self.delete_button = tk.Button(master, text="Delete Account", command=self.delete_account_window)
        self.delete_button.pack()

        self.view_button = tk.Button(master, text="View Account", command=self.view_account_window)
        self.view_button.pack()

        self.list_button = tk.Button(master, text="List Accounts", command=self.list_accounts)
        self.list_button.pack()

        self.generate_button = tk.Button(master, text="Generate Password", command=self.generate_password_window)
        self.generate_button.pack()

        self.quit_button = tk.Button(master, text="Quit", command=master.quit)
        self.quit_button.pack()

    def add_account_window(self):
        top = tk.Toplevel(self.master)
        top.title("Add Account")

        account_name_label = tk.Label(top, text="Account Name:")
        account_name_label.pack()
        account_name_entry = tk.Entry(top)
        account_name_entry.pack()

        username_label = tk.Label(top, text="Username:")
        username_label.pack()
        username_entry = tk.Entry(top)
        username_entry.pack()

        password_label = tk.Label(top, text="Password:")
        password_label.pack()
        password_entry = tk.Entry(top)
        password_entry.pack()

        add_button = tk.Button(top, text="Add", command=lambda: self.add_account(
            top, account_name_entry.get(), username_entry.get(), password_entry.get()))
        add_button.pack()

    def add_account(self, window, account_name, username, password):
        self.password_manager.add_account(account_name, username, password)
        messagebox.showinfo("Success", "Account added successfully.")
        window.destroy()

    def update_account_window(self):
        top = tk.Toplevel(self.master)
        top.title("Update Account")

        account_name_label = tk.Label(top, text="Account Name:")
        account_name_label.pack()

        account_names = list(self.password_manager.data.keys())
        account_name_var = tk.StringVar(top)
        account_name_var.set(account_names[0] if account_names else "")
        account_name_optionmenu = tk.OptionMenu(top, account_name_var, *account_names)
        account_name_optionmenu.pack()

        username_label = tk.Label(top, text="Username:")
        username_label.pack()
        username_entry = tk.Entry(top)
        username_entry.pack()

        password_label = tk.Label(top, text="Password:")
        password_label.pack()
        password_entry = tk.Entry(top)
        password_entry.pack()

        update_button = tk.Button(top, text="Update", command=lambda: self.update_account(
            top, account_name_var.get(), username_entry.get(), password_entry.get()))
        update_button.pack()

    def update_account(self, window, account_name, username, password):
        self.password_manager.update_account(account_name, username, password)
        messagebox.showinfo("Success", "Account updated successfully.")
        window.destroy()

    def delete_account_window(self):
        top = tk.Toplevel(self.master)
        top.title("Delete Account")

        account_name_label = tk.Label(top, text="Account Name:")
        account_name_label.pack()

        account_names = list(self.password_manager.data.keys())
        account_name_var = tk.StringVar(top)
        account_name_var.set(account_names[0] if account_names else "")
        account_name_optionmenu = tk.OptionMenu(top, account_name_var, *account_names)
        account_name_optionmenu.pack()

        delete_button = tk.Button(top, text="Delete", command=lambda: self.delete_account(
            top, account_name_var.get()))
        delete_button.pack()

    def delete_account(self, window, account_name):
        self.password_manager.delete_account(account_name)
        messagebox.showinfo("Success", "Account deleted successfully.")
        window.destroy()

    def view_account_window(self):
        top = tk.Toplevel(self.master)
        top.title("View Account")

        account_name_label = tk.Label(top, text="Account Name:")
        account_name_label.pack()

        account_names = list(self.password_manager.data.keys())
        account_name_var = tk.StringVar(top)
        account_name_var.set(account_names[0] if account_names else "")
        account_name_optionmenu = tk.OptionMenu(top, account_name_var, *account_names)
        account_name_optionmenu.pack()

        view_button = tk.Button(top, text="View", command=lambda: self.view_account(
            top, account_name_var.get()))
        view_button.pack()

    def view_account(self, window, account_name):
        account = self.password_manager.get_account(account_name)
        if account:
            messagebox.showinfo("Account Details", f"Username: {account['username']}\nPassword: {account['password']}")
        else:
            messagebox.showerror("Error", f"Account '{account_name}' not found.")
        window.destroy()

    def list_accounts(self):
        accounts = self.password_manager.list_accounts()
        if accounts:
            messagebox.showinfo("Account List", accounts)
        else:
            messagebox.showinfo("Account List", "No accounts found.")

    def generate_password_window(self):
        top = tk.Toplevel(self.master)
        top.title("Generate Password")

        account_name_label = tk.Label(top, text="Account Name:")
        account_name_label.pack()

        account_names = list(self.password_manager.data.keys())
        account_name_var = tk.StringVar(top)
        account_name_var.set(account_names[0] if account_names else "")
        account_name_optionmenu = tk.OptionMenu(top, account_name_var, *account_names)
        account_name_optionmenu.pack()

        length_label = tk.Label(top, text="Password Length:")
        length_label.pack()
        length_entry = tk.Entry(top)
        length_entry.pack()

        generate_button = tk.Button(top, text="Generate", command=lambda: self.generate_password(
            top, account_name_var.get(), length_entry.get()))
        generate_button.pack()

    def generate_password(self, window, account_name, length):
        try:
            length = int(length)
        except ValueError:
            messagebox.showerror("Error", "Password length must be an integer.")
            return
        password = self.password_manager.generate_password(length)
        self.password_manager.update_account(account_name, self.password_manager.data[account_name]['username'], password)
        messagebox.showinfo("Success", f"New password generated and updated for account '{account_name}'.")
        window.destroy()

def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
