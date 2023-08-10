from pwn import *

binary = './filename' # This should be the relative path to the ELF
e = elf(binary)
# Process pipe - Uncomment the one that's relevant for this use-case
p = process(e)
# uncomment for remote CTF server
# hostname = 'ctf.example.com'
# port = 22
# p = remote(hostname, port)

# NOTE: If you're connectting to a remote flag server, you may have to do 
#    additional steps (such as providing a ticket or solving a challenge).
#    This would be a good spot to do those items:

# EXAMPLE:
# ticket = "my.super.long.team.ctf.ticket.DEADBEEF.CAFEBABE"
# p.sendlineafter(b'Ticket please: ', ticket)

####
# Payload section
####

# You can communicate with the process using p.send(...) and other methods
# See https://docs.pwntools.com/en/stable/tubes.html for more info

# Most challenge would run their payload here, then listen for a flag

# You might listed for a flag using something similar to the following:
# (this example will likely need to be updated with the challenges actual
# flag format)
# p.recvuntil(b'flag{', timeout=10)
# flag = b'flag{' + p.recvuntil(b'}')
# log.info(flag)