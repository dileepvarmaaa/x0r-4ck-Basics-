# x0r-4ck-Basics-
From all writeups given for ctf are together gathered for next ctf use x0r}{4ck


https://github.com/shawnduong/ctf-writeups/blob/master/2019-TJ/Cryptography/guess-my-hashword.md
{ for md5 hash base questions refer the above link }

-----------------------------------------------------------------------------------------------------------------------------

BIT FLIPPING BASIC CHALLENGE FROM ANGSTROM CTF :-


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
