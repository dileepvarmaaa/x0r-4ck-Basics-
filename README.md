# x0r-4ck-Basics-
From all writeups given for ctf are together gathered for next ctf use x0r}{4ck

FOR MD5 HASHING BASED QUESTIONS REFER TO THIS :-

https://github.com/shawnduong/ctf-writeups/blob/master/2019-TJ/Cryptography/guess-my-hashword.md

-----------------------------------------------------------------------------------------------------------------------------

BIT FLIPPING BASIC CHALLENGE FROM ANGSTROM CTF 2019:-


Secret Sheep Society - 120 points - 95 solves
Attack againgst AES-CBC mode.
We get a cookie {"admin": false, "handle": "bam"} AES-CBC encrypted with a known IV. By carefully modifying the IV, we can change the string false in the first block to true.

The string false appears at indices 10 to 15 of the first block. Therefore, with C the being the first block, setting

IV[10:15] = C[10:15] ^ 'false' ^ 'true '
will make the the admin parameter to true in the decrypted cookie.

Here is the python implementation:

import requests

import re

from Crypto.Util.strxor import strxor

from base64 import *

url = 'https://secretsheepsociety.2019.chall.actf.co/'

cookie = "ZuNJ2xfy2eIegJsWEYmVTEwU63bTiSUAieVy8eVd+/qlqzDixgBcrqU6pHRIAsrY0C4/Uz1XTpreWMugeC8Fxw=="

ct = b64decode(cookie)

payload = ct[:10]+strxor(strxor(ct[10:15],b'false'),b'true ')+ct[15:]

r = requests.get(url,cookies={'token':b64encode(payload).decode()})

print(re.findall('actf{.*}',r.text))

which outputs the flag actf{shep_the_conqueror_slumbers}.

-----------------------------------------------------------------------------------------------------------------------------
Runes - 70 points - 234 solves ~~ ANGSTROM CTF 2019

PAILLIER CRYPTO~SYSTEM

We are given numbers n, g, c and the hint Paillier. Googling for it, we discover the Paillier cryptosystem, which is based on the hardness of decisional composite residuosity assumption, which is weaker than integer factorization. This is good news since the parameter n is easily factored.

It is then a matter of copy-pasting the algorithm on Wikipedia to get the flag:

from math import gcd

from Crypto.Util.number import inverse

from binascii import unhexlify

n= 99157116611790833573985267443453374677300242114595736901854871276546481648883

g= 99157116611790833573985267443453374677300242114595736901854871276546481648884

c= 2433283484328067719826123652791700922735828879195114568755579061061723786565164234075183183699826399799223318790711772573290060335232568738641793425546869

p = 310013024566643256138761337388255591613

q = 319848228152346890121384041219876391791

assert n == p*q

def L(x):
    
    return (x-1)//n

lamb = (p-1)*(q-1)//gcd(p-1,q-1)

mu = inverse(L(pow(g,lamb,n**2)),n)

m = L(pow(c,lamb,n**2))*mu%n

print(unhexlify(hex(m)[2:]))

which ouptuts the flag actf{crypto_lives}.

-----------------------------------------------------------------------------------------------------------------------------
