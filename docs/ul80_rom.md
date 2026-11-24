# ul80 options for ROM images

Use these options to link a program for a ROM. One example is the Z80 sound
CPU of a Neo Geo (ROM at 0000h to 7FFFh, RAM at F800h to FFFFh). The options
work for any Z80 ROM. If you use none of the options, ul80 links the program
in the same way as before.

## Layout

A ROM program has code in ROM and variables in RAM. The ROM image has the
initial bytes of the variables (DSEG). The startup code copies the bytes to
RAM.

```
ul80 --bin -p 68 -d F800 --rom-data --rom-size 8000 --fill FF \
     --ram-size 800 --min-stack 100 -o rom.bin -S rom.sym crt0.rel main.rel libc.lib
```

## Options

- `-d ADDR`, `--data-origin ADDR`: place DSEG at ADDR (in hexadecimal).
  COMMON follows DSEG. The option `/D:` of LINK-80 (L80) does the same.
  Without `--rom-data`, the image has the bytes of DSEG at ADDR.
- `--common-origin ADDR`: place COMMON (the BSS) at ADDR (in hexadecimal).
  The default is the end of DSEG.
- `--rom-data`: store the initial bytes of DSEG in the image directly after
  the code. Each DSEG symbol keeps its RAM address (the run address).
  - Use the option with `--bin` or `-x`.
  - With .COM, .PRL or .SPR output, the option is a usage error. Those
    outputs write the DSEG bytes at the RAM address.
  - The option needs `--data-origin`.
  - With the option, a COMMON block with initial bytes is an error. No code
    copies COMMON to RAM. Put initialized data in DSEG.
- `--bin`: write a raw binary file.
  - The file starts at the origin (`-p`), or at the lowest byte loaded if
    that byte is lower than the origin.
  - The file has no CP/M padding to 128 bytes.
  - ul80 writes the fill byte in each gap between loaded bytes.
  - The default file name has the extension `.bin`.
  - If you use `--rom-size`, you must also give `-p`. With `-p`, the first
    byte of the file is not a guess. For a ROM at 0000h, use `-p 0`.
- `--fill BYTE`: the fill byte (in hexadecimal, 00 to FF) for gaps and for
  the padding to `--rom-size`. The default is FF.
- `--rom-size N`: the size of the ROM in bytes (in hexadecimal). `--bin`
  pads the file to N bytes. If the image is larger than N, the link step
  fails.
- `--ram-end ADDR`: the first address after RAM (in hexadecimal, 10000 for
  the top of memory). If DSEG and COMMON end after ADDR, the link step fails.
- `--ram-size N`: the size of RAM (in hexadecimal). ul80 counts the size from
  `--data-origin`. The option `--ram-size` makes the same check as
  `--ram-end`.
- `--min-stack N`: N bytes (in hexadecimal) that must stay free in RAM after
  COMMON. The stack is in this space. The link step fails if fewer than N
  bytes are free. The check cannot see how deep the stack really goes.
- `--equ-file FILE`: write every public symbol as `NAME EQU 0xxxxH`. See the
  section "Banks".
- `--verbose`: write one line with the use of ROM and RAM. ul80 also writes
  the line when a limit fails.

## Symbols that `--rom-data` defines

- `__DATA_ROM`: the address in ROM of the initial data. The address is the
  first address after the code and after all absolute segment (ASEG) code.
- `__DATA_RAM`: the address in RAM where the data runs (the data origin).
- `__DATA_LEN`: the size in bytes of the initial data.
- `__DATA_END`: `__DATA_RAM` plus `__DATA_LEN`.
- `__BSS_START`, `__BSS_END`, `__END__`: the COMMON block and the end of RAM
  in use. The three symbols are RAM addresses.

The startup code does the steps that follow:

1. Load SP.
2. Copy `__DATA_LEN` bytes from `__DATA_ROM` to `__DATA_RAM` (LDIR).
3. Clear the bytes from `__BSS_START` to `__BSS_END`.
4. Call `main`, then loop on HALT.

Without `--rom-data`, ul80 does not define the four symbols `__DATA_ROM`,
`__DATA_RAM`, `__DATA_LEN` and `__DATA_END`.

## Symbol `__RAM_END`

When you give `--ram-end` or `--ram-size`, ul80 defines `__RAM_END`, the
first address after RAM. The startup code can use `__RAM_END` for
`LD SP,__RAM_END`. The top of memory (10000h) reads as 0000h, which is right
for a stack.

Without the two options, ul80 does not define `__RAM_END`. A reference to
`__RAM_END` is then an undefined-symbol error. Data or COMMON that ends after
10000h is an error when you use `-d`.

## Hex output

With `--rom-data` or `--data-origin`, `-x` writes each loaded run of bytes at
its load address and skips the gaps. Without these options, `-x` is the same
as before.

## Vectors in ASEG

A module can put the vectors in ASEG (`ORG 0` for reset, `ORG 38H` for the
IM 1 interrupt, `ORG 66H` for NMI) and the program code in CSEG. Two layouts
work:

- Put the vector module first on the command line. ul80 places the CSEG of
  the next module above the vector bytes (the rule of L80). If you set the
  origin above the vectors with `-p 68` or `-p 100`, the vectors can be in
  the same module as the startup code.
- Set the origin with `-p` to an address above the last vector byte.

If CSEG code is at an address that ASEG code also uses, the link step fails
with an overlap error. Use `--allow-overlap` only for a deliberate patch.

## Not done

- The BSS is zero in the image only when you clear the BSS in the startup
  code. The image has no bytes for COMMON.
- The tools do not model bank switching. Link each bank as a separate image
  (see the section "Banks").

## Banks

To link a program with banks, do these steps:

1. Link the common image first. Write its symbols with
   `--equ-file common.equ`.
2. Put the line `INCLUDE common.equ` in a module of a bank. The module can
   then call the common routines and read the common variables.
3. Link each bank with its own `-p` (for example `-p 8000`) and `--bin`.

The tests in `tests/test_ul80_rom.py` show these steps with one common image
and one bank. A symbol of the common image that has the same name as a symbol
in the bank is a duplicate-name error in the assembler.
