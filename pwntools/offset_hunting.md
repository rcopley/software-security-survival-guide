# Offset hunting with cyclic patterns
Pwntools provides a built-in [de Bruijn sequence](https://en.wikipedia.org/wiki/De_Bruijn_sequence)
generator. This is particularly helptful for finding offsets into strings 
from a buffer you control.

## Theory
Recall that most major processor arcitectures (i386, amd64, and arm) have a `ret`
instructions that pops and address off the stack and jumps to it. If an attacker
can overwrite that value in memory with a different address, they can hijack 
control of the application. Return addresses are not the only valuable thing
stored on the stack. Local variables, which are also stored on the stack, can be
overwritten in this way too.

## Using cyclic patterns with buffer overflows
Pwntools cyclic function can create a sequence of characters that is unique for
any n character long substring. Pwntools also provides a method to find the 
offset into such a cyclic sequence given an n-byte long string that's contained
in the sequence.

Once an attacker has identified that a buffer overflow is present, a cyclic 
pattern is useful to quickly identify how much padding is needed before the 
payload. It tells you how many bytes your need to send before you're overwriting
the portion of memory that you care about.

## Function jumping with buffer overflows
[buffer_overflow_1.md](buffer_overflow_1.md) contains an example of using a 
buffer overflow to jump to another function within the application. Review that
walkthrough to build familiarity with the techneique. That challenge makes 
things easier than it would normally be, however. Most programs do not announce
the address they're returning to, so how do we manipulate that address without 
seeing it? That's where GDB comes in.

The screenshots in this document utilize [pwndbg](https://github.com/pwndbg/pwndbg),
a GDB plug-in that provides a lot of convieneces for reverse engineering.

