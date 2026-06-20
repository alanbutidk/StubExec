# StubExec
**StubExec** is the tool that can deal with the stupid programs which require 
a *Executable*to function.
It stubs a executable with magic to generate a .exe or ELF.

Written in python and extremly simple C that a kid could learn,
It is a very simple tool to use...

---

## How to use it

This is the correct way to use this tool: 
```StubExec.py --print "Sentence"``` or ```StubExec.py```

By default, StubExec stubs a executable with ```Hi from stubexec!```

---

## How to build it
Very simple, clone this repo using: ```git clone https://github.com/alanbutidk/StubExec```,

and ```cd StubExec```, then just run ```make```

### Dependencies
**Almost no dependencies, except 2/3.**
They being: _GCC_, _Clang_.

> Windows users listen carefully: A tip for you, get [msys2](https://msys2.org).
It has every dependencies downloadable, just use pacman for UCRT Shell

and follow the setup instructions CAREFULLY...

# LICENSE

Licensed using [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html), found inside the repository
