# dbg2elf prototype

This folder holds the prototype of `dbg2elf` from phase 0 of the cpmemu
debugger plan
([docs/debugger_plan.md](https://github.com/avwohl/cpmemu/blob/main/docs/debugger_plan.md)).
The prototype is not a tool. `dbg2elf` (`um80/dbg2elf.py`, see
[docs/gdb.md](../../docs/gdb.md)) replaces the prototype.
The folder stays because the tests use `sumto.mac` and `sumto.c`.

`dbg2elf_proto.py` reads a `.mac` file with `;#line` markers, its `.PRN`
listing and its `.COM`. The prototype writes an ELF32 file for the z80 target
of GDB. The ELF32 file has DWARF 4 line rows, two subprograms and one global.

Run the prototype from this folder:

```
um80 -l sumto.prn -o sumto.rel sumto.mac
ul80 -o sumto.com sumto.rel
VARIANT=B python3 dbg2elf_proto.py sumto.mac sumto.prn sumto.com sumto.elf "$PWD"
z80-unknown-elf-gdb -batch sumto.elf -ex 'info line sumto.c:14' -ex 'disassemble /s main'
```

`VARIANT=B` writes each line of a merged group as a statement row.
Rule D4 of the plan now requires this row type.
Without `VARIANT=B`, the prototype writes the rule of the first draft.
GDB 18.1 cannot break on the rule of the first draft.
