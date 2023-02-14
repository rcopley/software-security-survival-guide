Often times the best place to start with a CTF executable is to run it. This 
will give you insight into the intended flow of the application and might help 
focus your reverse engeering efforts.

In addition to running the program blind, there are a few tools that are 
commonly used when triaging ctf challenges:
  * `strings` - as the name suggests, strings is a utility used for printing
  strings within an executable (or any other file). For basic ctf challenges 
  this might reveal a flag or password used in the program however most 
  challenges won't make it that easy.
  * `strace` - strace is an extremely useful tool for quickly examining the 
  innerworkings of a challege. Strace will log syscalls made by the program
  which can identify files, envrionmentment variables or other functionality
  that the program makes use of.
  *  `ltrace` - ltrace logs calls to shared libraries.