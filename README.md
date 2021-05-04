# small-shell
Mimicks a shell on Linux

1. Place file on Linux machine
2. Execute command "gcc --std=gnu99 -o smallsh smallsh.c"
3. Execute command "./smallsh"


## Description
This program mimicks a shell. The commands cd, exit, and status are built in.
  All other commands are passed to the exec() family of functions.

  Supported input format:
  command [arg1 arg2 ...] [< input_file] [> output_file] [&]

  Supported Features
  - blank lines
  - comment lines (#this is an example comment line, it must start with #)
  - exit
  - cd
  - status (returns the... )
  - all other standard commands
  - up to 512 arguments for one command
  - input and output redirection
  - using & at the end of a command to run a process in the background
  
  Unsupported
  - midline comments
