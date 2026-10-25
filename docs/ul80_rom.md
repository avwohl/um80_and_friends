# ul80 options for ROM images

Use these options to link a program for a ROM, for example the Z80 sound CPU of a Neo Geo (ROM at 0000h to 7FFFh, RAM at F800h to FFFFh). The options work for any Z80 ROM. If you use none of them, the link is the same as before.

## Layout

A ROM program has code in ROM and variables in RAM. The initial bytes of the variables (DSEG) are in the ROM image. The startup code copies them to RAM.

```
ul80 --bin -p 68 -d F800 --rom-data --rom-size 8000 --fill FF \
     --ram-size 800 --min-stack 100 -o rom.bin -S rom.sym crt0.rel main.rel libc.lib
```

## Options

- `-d ADDR`, `--data-origin ADDR`: place DSEG at ADDR (hex). COMMON follows DSEG. The LINK-80 `/D:` switch does the same. Without `--rom-data`, the bytes of DSEG are in the image at ADDR.
- `--common-origin ADDR`: place COMMON (the BSS) at ADDR (hex). The default is the end of DSEG.
- `--rom-data`: store the initial bytes of DSEG in the image directly after the code. Each DSEG symbol keeps its RAM address (the run address). This option needs `--data-origin`. A COMMON block with initial bytes is an error with this option, because no code copies COMMON to RAM. Put initialised data in DSEG.
- `--bin`: write a raw binary file. The file starts at the origin (`-p`), or at the lowest byte loaded if that is lower. The file has no CP/M padding to 128 bytes. A gap between loaded bytes has the fill byte. The default file name has the extension `.bin`.
- `--fill BYTE`: the fill byte (hex) for gaps and for the padding to `--rom-size`. The default is FF.
- `--rom-size N`: the size of the ROM in bytes (hex). `--bin` pads the file to N bytes. If the image is larger than N, the link fails.
- `--ram-end ADDR`: the first address after RAM (in hex, 10000 for the top of memory). If DSEG and COMMON end after ADDR, the link fails.
- `--ram-size N`: the size of RAM (hex), counted from `--data-origin`. `--ram-size` makes the same check as `--ram-end`.
- `--min-stack N`: bytes (hex) that must stay free in RAM after COMMON. The stack is there. The link fails if less than N bytes are free. The check cannot see how deep the stack really goes.
- `--verbose`: print one line with the ROM and RAM use. The line is also printed when a limit fails.

## Symbols that `--rom-data` defines

- `__DATA_ROM`: the address in ROM of the initial data. This address is the first address after the code and after all absolute (ASEG) code.
- `__DATA_RAM`: the address in RAM where the data runs (the data origin).
- `__DATA_LEN`: the size in bytes of the initial data.
- `__DATA_END`: `__DATA_RAM` plus `__DATA_LEN`.
- `__BSS_START`, `__BSS_END`, `__END__`: the COMMON block and the end of RAM in use. They are RAM addresses.

The startup code does this:

1. Load SP.
2. Copy `__DATA_LEN` bytes from `__DATA_ROM` to `__DATA_RAM` (LDIR).
3. Clear the bytes from `__BSS_START` to `__BSS_END`.
4. Call `main`, then loop on HALT.

Without `--rom-data` these four symbols are not defined.

## Hex output

With `--rom-data` or `--data-origin`, `-x` writes each loaded run of bytes at its load address and skips the gaps. Without these options, `-x` is the same as before.

## Vectors in ASEG

A module can put the vectors in ASEG (`ORG 0` for reset, `ORG 38H` for the IM 1 interrupt, `ORG 66H` for NMI) and the program code in CSEG. Two layouts work:

- Put the vector module first on the command line. ul80 places the CSEG of the next module above the vector bytes (the LINK-80 rule). The vectors can be in the same module as the startup code if you set the origin above them with `-p 68` or `-p 100`.
- Set the origin with `-p` to an address above the last vector byte.

If CSEG code is at an address that ASEG code also uses, the link fails with an overlap error. Use `--allow-overlap` only for a deliberate patch.

## Not done

- The BSS is zero in the image only when you clear it in the startup code. The image has no bytes for COMMON.
- The tools do not model bank switching. Link each bank as a separate image.
