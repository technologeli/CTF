---
category: crypto
---
# crypto-civilization

## Information
This challenge references a viral Minecraft YouTube Series called [Parkour Civilization](https://www.youtube.com/watch?v=2pFwQiwRbcg). The series starts with the narrator having to choose between eating raw chicken or raw beef, but needing to complete a difficult challenge to get the beef.

We are given `civ.py` and `Dockerfile`.

In this case, the `Dockerfile` is only relevant since there is a time limit:
```Dockerfile
FROM pwn.red/jail

COPY --from=python:3.12-slim-bookworm / /srv
COPY chall.py /srv/app/run
COPY flag.txt /srv/app/flag.txt
RUN chmod 755 /srv/app/run

ENV JAIL_MEM=20M
ENV JAIL_TIME=300
```

`civ.py` is a long Python script, but it goes as follows:
- `PRG(s)` reads in a 2-byte value and returns a 4-byte value generated from the first 4 bytes of SHA3-256 algorithm.
- Of 200 attempts, the user must succeed in 133 "commits."
- A commit consists of the following:
	- A random `y` from `urandom`
	- A user input for a 4-byte `com`
	- A 50/50 split between the chicken (easy) path and the beef (hard) path.
- The chicken (easy) path:
	- A user input 2-byte `decom` that must satisfy `PRG(decom) == com`
- The beef (hard) path:
	- A user input 2-byte `decom` that must satisfy `PRG(decom) ^ y == com`


After the user gets at least 133 attempts correct, they get the flag.

## Solution
Since `PRG(s)` takes in only two bytes, there are `256*256=65536` inputs and outputs. We can create a map between them.

We can easily solve the chicken path using this map. As long as we choose a `com` that is in the map, it has a `decom`.

The beef is harder, however. We can rearrange `PRG(decom) ^ y == com` to `PRG(decom) == com ^ y`, Given our previously chosen `com` and `y`, all we need to do is find the `decom` that results in this XOR result.

Unfortunately, due to the `Dockerfile` and the comment at the start of the Python file, we only have 1.5 seconds per commit to make to find the `decom`. To solve this issue, I ran through as many random samples as I could within 1.5 seconds in an attempt to find the solution. If I did, I sent it, but otherwise I accepted that I got the problem wrong and moved on.

My script `solve.py` runs as necessary but does not have a 100% success rate. Sometimes, I just fall short of 133/200.