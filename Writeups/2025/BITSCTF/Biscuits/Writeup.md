---
category: pwn
---
# Biscuits

## Information
We are given a netcat IP and a binary.

Running the binary gives this:
![[Pasted image 20250218165815.png]]

## Reversing
Using `strings` we can find all the available cookies. In https://dogbolt.org/ we can see that it uses `srand(time(NULL))`:
![[Pasted image 20250218170034.png]]

If we get all 100 correct, we get the flag:
![[Pasted image 20250218170102.png]]
## Exploitation
`srand(time(NULL))` is vulnerable since this is run on connection. Because of this, we can write a copy using the same C standard library implementation (likely glibc). `time(NULL` returns the seconds since the Unix Epoch, Jan 1, 1970. If we can start a similar process at the same time, we will get exactly the same biscuits. 

Here is `mirror.c`, my program that generates the 100 random cookies.
```c
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
char *cookies[100] = {
	"Chocolate Chip",
	"Sugar Cookie",
	"Oatmeal Raisin",
	"Peanut Butter",
	"Snickerdoodle",
	"Shortbread",
	"Gingerbread",
	"Macaron",
	"Macaroon",
	"Biscotti",
	"Butter Cookie",
	"White Chocolate Macadamia Nut",
	"Double Chocolate Chip",
	"M&M Cookie",
	"Lemon Drop Cookie",
	"Coconut Cookie",
	"Almond Cookie",
	"Thumbprint Cookie",
	"Fortune Cookie",
	"Black and White Cookie",
	"Molasses Cookie",
	"Pumpkin Cookie",
	"Maple Cookie",
	"Espresso Cookie",
	"Red Velvet Cookie",
	"Funfetti Cookie",
	"S'mores Cookie",
	"Rocky Road Cookie",
	"Caramel Apple Cookie",
	"Banana Bread Cookie",
	"Zucchini Cookie",
	"Matcha Green Tea Cookie",
	"Chai Spice Cookie",
	"Lavender Shortbread",
	"Earl Grey Tea Cookie",
	"Pistachio Cookie",
	"Hazelnut Cookie",
	"Pecan Sandies",
	"Linzer Cookie",
	"Spritz Cookie",
	"Russian Tea Cake",
	"Anzac Biscuit",
	"Florentine Cookie",
	"Stroopwafel",
	"Alfajores",
	"Polvor",
	"Springerle",
	"Pfeffern",
	"Speculoos",
	"Kolaczki",
	"Rugelach",
	"Hamantaschen",
	"Mandelbrot",
	"Koulourakia",
	"Melomakarona",
	"Kourabiedes",
	"Pizzelle",
	"Amaretti",
	"Cantucci",
	"Savoiardi (Ladyfingers)",
	"Madeleine",
	"Palmier",
	"Tuile",
	"Langue de Chat",
	"Viennese Whirls",
	"Empire Biscuit",
	"Jammie Dodger",
	"Digestive Biscuit",
	"Hobnob",
	"Garibaldi Biscuit",
	"Bourbon Biscuit",
	"Custard Cream",
	"Ginger Nut",
	"Nice Biscuit",
	"Shortcake",
	"Jam Thumbprint",
	"Coconut Macaroon",
	"Chocolate Crinkle",
	"Pepparkakor",
	"Sandbakelse",
	"Krumkake",
	"Rosette Cookie",
	"Pinwheel Cookie",
	"Checkerboard Cookie",
	"Rainbow Cookie",
	"Mexican Wedding Cookie",
	"Snowball Cookie",
	"Cranberry Orange Cookie",
	"Pumpkin Spice Cookie",
	"Cinnamon Roll Cookie",
	"Chocolate Hazelnut Cookie",
	"Salted Caramel Cookie",
	"Toffee Crunch Cookie",
	"Brownie Cookie",
	"Cheesecake Cookie",
	"Key Lime Cookie",
	"Blueberry Lemon Cookie",
	"Raspberry Almond Cookie",
	"Strawberry Shortcake Cookie",
	"Neapolitan Cookie",
};

int main() {
	srand(time(0));
	for (int i = 0; i < 100; i++) {
		int r = rand() % 100;
		printf("%s\n", cookies[r]);
	}
	return 0;
}
```

We can compile this and grab all of the cookies from our mirror program to send to main:
```python
from pwn import *

local = process("./a.out")
cookies = local.recvall().decode().strip().split("\n")

exe = process("./main")

for cookie in cookies:
    print(exe.recvuntil(b": "))
    sleep(0.1)
    info(cookie.encode())
    exe.sendline(cookie.encode())

exe.interactive()
```