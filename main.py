import os
import json
import base64
import random
import string
import hashlib
from datetime import datetime
import requests
from captcha.image import ImageCaptcha
from PIL import ImageTk, Image
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

BLOCKCHAIN_FILE = 'blockchain.json'
PRIVATE_KEYS_FILE = 'private_keys.json'
CONFIG_FILE = "config.dat"
MAX_ATTEMPTS = 3
MIN_PASSWORD_LENGTH = 8
MAX_DAYS = 30
MAX_RUNS = 20
CAPTCHA_TEXT = ""
KEYWORD = "vigenerekey"
UNLOCK_KEY = "mysecretunlockkey"

def random_text(length=6):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for _ in range(length))

def generate_captcha():
    global CAPTCHA_TEXT
    CAPTCHA_TEXT = random_text()
    image_captcha = ImageCaptcha(width=280, height=90, fonts=["arial.ttf"])
    captcha_image = image_captcha.generate_image(CAPTCHA_TEXT)
    captcha_image.save('captcha.png')
    return 'captcha.png'

def vigenere_encrypt(text, key):
    encrypted = []
    key = key * (len(text) // len(key)) + key[:len(text) % len(key)]
    for t, k in zip(text, key):
        encrypted.append(chr((ord(t) + ord(k)) % 256))
    return base64.urlsafe_b64encode("".join(encrypted).encode()).decode()

def vigenere_decrypt(text, key):
    text = base64.urlsafe_b64decode(text.encode()).decode()
    decrypted = []
    key = key * (len(text) // len(key)) + key[:len(text) % len(key)]
    for t, k in zip(text, key):
        decrypted.append(chr((ord(t) - ord(k)) % 256))
    return "".join(decrypted)

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {"first_run_date": str(datetime.now().date()), "run_count": 0}
    with open(CONFIG_FILE, "r") as f:
        data = vigenere_decrypt(f.read(), KEYWORD)
        return json.loads(data)

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        data = vigenere_encrypt(json.dumps(config), KEYWORD)
        f.write(data)

def get_internet_time():
    try:
        response = requests.get("http://worldtimeapi.org/api/timezone/Etc/UTC")
        if response.status_code == 200:
            data = response.json()
            return datetime.strptime(data["datetime"][:19], "%Y-%m-%dT%H:%M:%S")
    except Exception:
        pass
    return datetime.now()

def check_lock_status():
    config = load_config()
    first_run_date = datetime.strptime(config["first_run_date"], "%Y-%m-%d")
    current_date = get_internet_time()
    days_used = (current_date - first_run_date).days
    remaining_days = MAX_DAYS - days_used
    remaining_runs = MAX_RUNS - config["run_count"]
    if days_used > MAX_DAYS or config["run_count"] >= MAX_RUNS:
        return True, 0, 0
    config["run_count"] += 1
    save_config(config)
    return False, remaining_days, remaining_runs

def prompt_unlock():
    key = simpledialog.askstring("Розблокування", "Введіть ключ для розблокування програми:")
    if key == UNLOCK_KEY:
        config = load_config()
        config["run_count"] = 0
        config["first_run_date"] = str(datetime.now().date())
        save_config(config)
        messagebox.showinfo("Успіх", "Програму розблоковано!")
    else:
        messagebox.showerror("Помилка", "Невірний ключ!")

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def load_blockchain():
    if not os.path.exists(BLOCKCHAIN_FILE):
        with open(BLOCKCHAIN_FILE, 'w', encoding='utf-8') as f:
            json.dump([], f, ensure_ascii=False, indent=4)
    with open(BLOCKCHAIN_FILE, 'r', encoding='utf-8') as f:
        blockchain = json.load(f)
    ensure_admin_block(blockchain)
    return blockchain

def save_blockchain(blockchain):
    with open(BLOCKCHAIN_FILE, 'w', encoding='utf-8') as f:
        json.dump(blockchain, f, ensure_ascii=False, indent=4)

def load_private_keys():
    if not os.path.exists(PRIVATE_KEYS_FILE):
        with open(PRIVATE_KEYS_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f, ensure_ascii=False, indent=4)
    with open(PRIVATE_KEYS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_private_keys(private_keys):
    with open(PRIVATE_KEYS_FILE, 'w', encoding='utf-8') as f:
        json.dump(private_keys, f, ensure_ascii=False, indent=4)

def ensure_admin_block(blockchain):
    admin_exists = any(block["username"] == "ADMIN" for block in blockchain)
    if not admin_exists:
        admin_password = random_text(32)
        admin_block = {
            "username": "ADMIN",
            "password_hash": hash_data(admin_password),
            "previous_hash": "",
            "transactions": []
        }
        blockchain.append(admin_block)
        save_blockchain(blockchain)
        private_keys = load_private_keys()
        private_keys["ADMIN"] = admin_password
        save_private_keys(private_keys)

def create_block(previous_hash, username, password):
    private_key = random_text(32)
    block = {
        "username": username,
        "password_hash": hash_data(password),
        "previous_hash": previous_hash,
        "transactions": []
    }
    return block, private_key

def find_user_block(blockchain, username):
    for block in blockchain:
        if block["username"] == username:
            return block
    return None

def add_transaction(block, data):
    transaction = {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "signature": hash_data(block["username"])[-10:],
        "information": data
    }
    block["transactions"].append(transaction)

class LoginApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Аутентифікація")
        self.master.geometry("400x400")
        self.blockchain = load_blockchain()
        self.private_keys = load_private_keys()
        self.attempts = 0
        self.create_widgets()

    def create_widgets(self):
        tk.Button(self.master, text="Реєстрація нового користувача", command=self.register_user, width=30).pack(pady=10)
        tk.Button(self.master, text="Перегляд блоків і транзакцій", command=self.view_blocks, width=30).pack(pady=10)

        tk.Label(self.master, text="Ім'я користувача:").pack()
        self.username_entry = tk.Entry(self.master)
        self.username_entry.pack()

        tk.Label(self.master, text="Пароль:").pack()
        self.password_entry = tk.Entry(self.master, show="*")
        self.password_entry.pack()

        captcha_image = generate_captcha()
        self.captcha_img = ImageTk.PhotoImage(Image.open(captcha_image))
        self.captcha_label = tk.Label(self.master, image=self.captcha_img)
        self.captcha_label.pack(pady=10)

        tk.Button(self.master, text="Перегенерувати CAPTCHA", command=self.refresh_captcha).pack()

        tk.Label(self.master, text="Введіть CAPTCHA:").pack()
        self.captcha_entry = tk.Entry(self.master)
        self.captcha_entry.pack()

        tk.Button(self.master, text="Вхід", command=self.login).pack(pady=10)

    def refresh_captcha(self):
        captcha_image = generate_captcha()
        self.captcha_img = ImageTk.PhotoImage(Image.open(captcha_image))
        self.captcha_label.configure(image=self.captcha_img)

    def register_user(self):
        username = simpledialog.askstring("Реєстрація", "Введіть ім'я користувача:")
        if not username:
            return
        if find_user_block(self.blockchain, username):
            messagebox.showerror("Помилка", "Користувач вже існує.")
            return

        password = simpledialog.askstring("Реєстрація", "Введіть пароль:", show="*")
        if not password:
            return
        confirm_password = simpledialog.askstring("Реєстрація", "Підтвердіть пароль:", show="*")
        if password != confirm_password:
            messagebox.showerror("Помилка", "Паролі не співпадають.")
            return

        previous_hash = hash_data(self.blockchain[-1]["username"] if self.blockchain else "")
        block, private_key = create_block(previous_hash, username, password)
        self.blockchain.append(block)
        self.private_keys[username] = private_key

        save_blockchain(self.blockchain)
        save_private_keys(self.private_keys)

        messagebox.showinfo("Успіх", f"Користувача зареєстровано! Закритий ключ: {private_key}")

    def view_blocks(self):
        window = tk.Toplevel(self.master)
        window.title("Блоки і транзакції")
        window.geometry("600x400")

        tree = ttk.Treeview(window, columns=("username", "transactions", "previous_hash"), show="headings")
        tree.heading("username", text="Користувач")
        tree.heading("transactions", text="Кількість транзакцій")
        tree.heading("previous_hash", text="Попередній хеш")
        tree.column("username", width=150)
        tree.column("transactions", width=150)
        tree.column("previous_hash", width=300)

        for block in self.blockchain:
            tree.insert("", "end", values=(
                block["username"],
                len(block["transactions"]),
                block["previous_hash"]
            ))

        tree.pack(fill="both", expand=True)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        captcha_input = self.captcha_entry.get().strip()

        if captcha_input.lower() != CAPTCHA_TEXT.lower():
            messagebox.showerror("Помилка", "Неправильна CAPTCHA.")
            return

        user_block = find_user_block(self.blockchain, username)

        if not user_block:
            messagebox.showerror("Помилка", "Користувач не знайдений.")
            return

        if username not in self.private_keys or self.private_keys[username] != password:
            self.attempts += 1
            remaining = MAX_ATTEMPTS - self.attempts
            if remaining > 0:
                messagebox.showerror("Помилка", f"Неправильний пароль. Залишилось спроб: {remaining}")
            else:
                messagebox.showerror("Заблоковано", "Превищено кількість спроб. Спробуйте пізніше.")
                self.master.destroy()
            return

        self.attempts = 0
        messagebox.showinfo("Успіх", f"Вітаємо, {username}!")
        self.master.withdraw()
        user_window = tk.Toplevel(self.master)
        UserApp(user_window, username, user_block, self.blockchain, save_blockchain)

class UserApp:
    def __init__(self, master, username, user_block, blockchain, save_func):
        self.master = master
        self.master.title(f"Користувач: {username}")
        self.master.geometry("400x300")
        self.username = username
        self.user_block = user_block
        self.blockchain = blockchain
        self.save_func = save_func
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.master, text=f"Ласкаво просимо, {self.username}!").pack(pady=20)
        tk.Button(self.master, text="Додати транзакцію", command=self.add_transaction).pack(pady=10)
        tk.Button(self.master, text="Вийти", command=self.logout).pack(pady=10)

    def add_transaction(self):
        data = simpledialog.askstring("Нова транзакція", "Введіть дані для транзакції:")
        if data:
            add_transaction(self.user_block, data)
            self.save_func(self.blockchain)
            messagebox.showinfo("Успіх", "Транзакцію додано!")

    def logout(self):
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.captcha_entry.delete(0, tk.END)
        self.refresh_captcha()
        self.master.destroy()
        self.master.deiconify()

def main():
    locked, remaining_days, remaining_runs = check_lock_status()
    if locked:
        root = tk.Tk()
        root.withdraw()
        if messagebox.askyesno("Програму заблоковано", "Термін дії завершився або перевищено кількість запусків.\n"
                                                      "Бажаєте ввести ключ для розблокування?"):
            prompt_unlock()
        else:
            return
    else:
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Інформація", f"Залишилось запусків: {remaining_runs}\nЗалишилось днів: {remaining_days}")
        root.destroy()
        root = tk.Tk()
        app = LoginApp(root)
        root.mainloop()

if __name__ == "__main__":
    main()
