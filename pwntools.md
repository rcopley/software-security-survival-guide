Pwntools is a python-based exploit framework that is extremely useful for 
binary exploitation challenges. Pwntools can be used to automate large portions
of the exploit process and provide a reliable method of exploit execution.

Pwntool's github repository has a [comprehensive set of tutorials](https://github.com/Gallopsled/pwntools-tutorial#readme) to get you up 
to speed with pwntools.

## Starter template
My pwntools template for local binaries looks similar to the following:
```python
from pwn import *

elf = ELF('path_to_binary')
p = elf.process()

context.log_level = 'debug' # Helpful for debugging and writing exploits

##
# Exploit code goes here
##
```

We can break down this starter template line-by-line:
  * `elf = ELF('path_to_binary')` - [`pwnlib.elf`](https://docs.pwntools.com/en/stable/elf/elf.html)
    gives you access to symbols and other information contained in the binary. 
    This makes it easy to craft ROP-based attacks and other exploits that take
    advantage of symbols and properties of the executable itself.
  * `p = elf.process()` - Provides a [`process`](https://docs.pwntools.com/en/stable/tubes/processes.html#pwnlib.tubes.process.process)
  tube which can be used to communicate with the process.
  * `context.log_level = 'debug'` - The debug log_level is useful when 
  initially developing exploits. It provides detailed information on data 
  recieved and sent to the executable. Having this setting initially on can
  help identify issues with your exploit that might otherwise be hidden. Once
  your exploit is reliable, this line can be removed to make the output from 
  the exploit script easier to read.

If you're communicating with an executable hosted on a remote server (such as
an `ncat` server commonly used on CTFs), then you will need to use pwntool's
`remote(host, port)` instead of process. In most cases you can craft your 
exploit using a local copy of the binary, then swap the `p = elf.process()`
line for `p = remote(host, port)` to run your exploit on the remote server.

## Helpful pwntools concepts
### Context options
https://docs.pwntools.com/en/stable/context.html

The `context` object is used to control the behavior of some functions within
pwntools. For instance, you could inform pwntools of the target architecture 
and os of the binary this way:
```python
context.arch = 'amd64'
context.os = 'linux'
```

The full list of context options is available at the pwntools documentation 
linked above. The common ones I use (with an example of usage) are:
  * `context.arch = amd64` - to set the target architecture of the binary
  * `context.os = linux` - to set the target os of the binary
  * `context.binary = '/path/to/binary'` - sets arch, os, endianness, and bits 
  based on a provided executable
  * `context.log_level = 'debug'` - provides debug output for various pwntools
  functions

### Getting data in and out
https://docs.pwntools.com/en/stable/tubes.html

Pwntools uses "tubes" to connect input and output from programs. This common
interface makes it easy to, among other things, retarget an attack from a local
binary to one running on an `ncat` server.

#### Useful receive methods
| Method                         | Description                                                |
|--------------------------------|------------------------------------------------------------|
| `.clean()`                     | Removes buffered data from a tube                          |
| `.recv(numb, timeout)`         | Receives up to `numb` bytes or until `timeout is exceeded  |
| `.recvuntil(delims)`           | Recieves until `delims` is seen. Returned value will include the specified `delims` |
| `.recvline()`                  | Recieves until a newline is seen. |
| `.recvall()`                   | Recieves until `EOF` is recieved  |

#### Useful send methods
| Method                         | Description                         |
|--------------------------------|-------------------------------------|
| `.send(data)`                  | Sends byte string `data` to process |
| `.sendline(data)`              | Sends byte string `data` with a newline afterwards |
| `.sendafter(delim, data)`      | Sends byte string `data` after `delim` is recieved |
| `.sendthen(delim, data)`       | Sends byte string `data` then waits for `delim` to be recieved |

## Debugging exploits
Pwntools has built-in support for starting a gdb debug session within your 
exploit. This is useful for checking if your exploit is actually doing what you
think it's doing.

Take the following exploit code as an example:
```python
from pwn import *
elf = ELF('pwnme')
p = elf.process()

g = cyclic_gen()
p.sendline(g.get(2000))
```

If we wanted to pause execution before the payload is sent, you could add the 
following line before `p.sendline(...)`:
```python
pid = gdb.attach(p)
```

This will spawn a gdb session and attach it to the specified process (in this 
case, our own process associated with `p`).

Alternatively, instead of attaching to a running process, you could use 
`gdb.debug()` to start a new instance of the process in a gdb session.