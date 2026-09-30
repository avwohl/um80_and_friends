# um80 - Microsoft MACRO-80 Compatible Toolchain for Linux

A complete Unix/Linux implementation of Microsoft's classic CP/M development tools from the 1980s:

- **um80** - MACRO-80 compatible assembler for 8080/Z80
- **ul80** - LINK-80 compatible linker
- **ulib80** - LIB-80 compatible library manager
- **ucref80** - Cross-reference utility
- **ud80** - 8080/Z80 disassembler for CP/M .COM files
- **ux80** - 8080 to Z80 assembly source translator

These tools can assemble, link, and manage 8080/Z80 assembly code to produce CP/M-compatible .COM executables on modern Linux systems.

## Installation

### From PyPI (recommended)

```bash
pip install um80
```

### From source

```bash
git clone https://github.com/avwohl/um80_and_friends.git
cd um80_and_friends
pip install -e .
```

## Quick Start

```bash
# Assemble source files
um80 -o main.rel main.mac
um80 -o util.rel util.mac

# Create a library
ulib80 -c mylib.lib helper.rel support.rel

# Link everything together
ul80 -o program.com main.rel util.rel mylib.lib

# Run in CP/M emulator
cpm program.com
```

Each tool has many more options. [docs/tools.md](https://github.com/avwohl/um80_and_friends/blob/main/docs/tools.md) has a command summary for each tool.

## Documentation

- [docs/tools.md](https://github.com/avwohl/um80_and_friends/blob/main/docs/tools.md): command summary, tools reference, file formats, installing the man pages
- [docs/compatibility.md](https://github.com/avwohl/um80_and_friends/blob/main/docs/compatibility.md): compatibility notes, extended symbol names, DRI syntax extensions (summary)
- [docs/EXTENSIONS.md](https://github.com/avwohl/um80_and_friends/blob/main/docs/EXTENSIONS.md): extensions beyond M80/L80, in full detail
- [docs/testing.md](https://github.com/avwohl/um80_and_friends/blob/main/docs/testing.md): the test suite, the M80 compatibility tests, the mbasic2025 byte-for-byte test
- [docs/mbasic2025.md](https://github.com/avwohl/um80_and_friends/blob/main/docs/mbasic2025.md): mbasic2025 built with um80/ul80 and with the genuine M80/L80
- [docs/index.md](https://github.com/avwohl/um80_and_friends/blob/main/docs/index.md): quick reference, examples, troubleshooting
- [docs/ISSUES.md](https://github.com/avwohl/um80_and_friends/blob/main/docs/ISSUES.md): open issues
- [CHANGELOG.md](https://github.com/avwohl/um80_and_friends/blob/main/CHANGELOG.md): release history
- Man pages: `man um80`, `man ul80`, `man ulib80`, `man ucref80`, `man ud80`, `man ux80`
- Original Microsoft manuals, in the
  [retro_docs](https://github.com/avwohl/retro_docs/tree/main/um80_and_friends) archive:
  - [`m80.pdf`](https://github.com/avwohl/retro_docs/blob/main/um80_and_friends/m80.pdf) - MACRO-80 assembler
  - [`l80.pdf`](https://github.com/avwohl/retro_docs/blob/main/um80_and_friends/l80.pdf) - LINK-80 linker
  - [`cref_lib.pdf`](https://github.com/avwohl/retro_docs/blob/main/um80_and_friends/cref_lib.pdf) - CREF and LIB-80
  - [`8080asm.pdf`](https://github.com/avwohl/retro_docs/blob/main/um80_and_friends/8080asm.pdf) - 8080 assembly reference

## License

GPL-3.0-or-later. See [LICENSE](https://github.com/avwohl/um80_and_friends/blob/main/LICENSE).


## Related Projects

- [80un](https://github.com/avwohl/80un) - Unpacker for the CP/M archive and compression formats LBR, ARC, squeeze, crunch, and CrLZH.
- [cpmdroid](https://github.com/avwohl/cpmdroid) - Z80/CP/M emulator for Android phones and tablets. It emulates the RomWBW HBIOS interface and a VT100 terminal.
- [cpmemu](https://github.com/avwohl/cpmemu) - Z80/CP/M emulator for Linux and Windows, with Z80 and 8080 CPU cores. It translates the BDOS and BIOS calls of CP/M 2.2 programs to the host file system.
- [ioscpm](https://github.com/avwohl/ioscpm) - Z80/CP/M emulator for iOS and macOS. It emulates the RomWBW HBIOS interface and runs CP/M 2.2 and CP/M 3.
- [learn-ada-z80](https://github.com/avwohl/learn-ada-z80) - Collection of more than 90 Ada example programs for uada80, the Ada compiler for the Z80 processor and CP/M.
- [mbasic](https://github.com/avwohl/mbasic) - Python interpreter for MBASIC 5.21, the Microsoft BASIC-80 for CP/M. Two compiler backends compile the programs to CP/M .COM files or to JavaScript.
- [mbasic2025](https://github.com/avwohl/mbasic2025) - Reconstruction of the lost source code of MBASIC 5.21, the Microsoft BASIC-80 for CP/M. The MACRO-80 source code assembles to a binary that matches mbasic.com byte for byte.
- [mbasicc](https://github.com/avwohl/mbasicc) - C++17 interpreter for MBASIC 5.21, the Microsoft BASIC-80 for CP/M. It runs on Linux and macOS.
- [mbasicc_web](https://github.com/avwohl/mbasicc_web) - Web browser interpreter for MBASIC 5.21, the Microsoft BASIC-80 for CP/M. Emscripten compiles the mbasicc interpreter to WebAssembly.
- [mpm2](https://github.com/avwohl/mpm2) - Z80 emulator for MP/M II, the multi-user CP/M operating system. Users connect over SSH, and SFTP clients transfer files.
- [romwbw_emu](https://github.com/avwohl/romwbw_emu) - Hardware-level Z80/CP/M emulator for Linux and macOS. It emulates the RomWBW HBIOS interface and switches banks in 512 KB of ROM and 512 KB of RAM.
- [scelbal](https://github.com/avwohl/scelbal) - Floating-point BASIC interpreter for the 8080 processor and CP/M. A translator converts the original 8008 source code to 8080 source code.
- [uada80](https://github.com/avwohl/uada80) - Ada compiler for the Z80 processor and CP/M 2.2. It compiles a subset of Ada 2012 to CP/M .COM files.
- [uc80](https://github.com/avwohl/uc80) - C compiler for the Z80 processor and CP/M. It optimizes for small code size.
- [ucow](https://github.com/avwohl/ucow) - Cowgol compiler for the Z80 processor and CP/M. It runs on Linux in Python.
- [upeepz80](https://github.com/avwohl/upeepz80) - Peephole optimizer for Z80 compilers that write lowercase Z80 assembly language. It shortens jumps to jr, builds djnz loops, and removes dead stores.
- [uplm80](https://github.com/avwohl/uplm80) - PL/M-80 compiler for the Z80 processor and CP/M. It writes Intel 8080 and Zilog Z80 assembly language.
- [z80cpmw](https://github.com/avwohl/z80cpmw) - Z80/CP/M emulator for Windows. It emulates the RomWBW HBIOS interface and boots CP/M from disk images.
