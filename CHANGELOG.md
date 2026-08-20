# Changelog

All notable changes to the um80 toolchain are documented here.

## [0.3.46] - 2026-08-04

### Fixed
- ul80 linker: An error recorded during an otherwise successful link is now
  reported. `main()` printed `linker.errors` only when `link()` returned false,
  but L80 keeps the first definition of a multiply-defined global and links on,
  so `link()` succeeds and every error recorded along the way was silently
  thrown away: exit 0, output written, nothing on stderr. This swallowed the
  multiply-defined PUBLIC error added in 0.3.42 on the command-line path, which
  went unnoticed because the test for it drives the `Linker` API rather than
  the entry point — the check worked, only the reporting did not. On the
  command line the diagnostic had been missing for two releases: through 0.3.41
  ul80 printed `Warning: Multiple definition of 'X'`, 0.3.42 made it an error
  that `main()` never reached, and 0.3.43 shipped that way. It now prints
  `Error: Multiply defined global 'X'`. Both CLI paths are covered now. The
  exit status stays 0 when the link still succeeded, matching L80, which
  accepts such link lines and produces output.

## [0.3.45] - 2026-08-04

### Fixed
- um80 assembler: The two-operand Z80 ALU forms `SUB/AND/XOR/OR/CP A,<operand>`
  no longer drop the operand. ADD, ADC and SBC each collapse a leading `A,` to
  the one-operand encoding; these five had no such branch, so `A` was taken as
  the operand and the real one was discarded — `CP A,5` assembled as `CP A`
  (BF, which always sets Z) rather than FE 05, `SUB A,5` as 97 rather than
  D6 05, `AND A,0FH` as A7 rather than E6 0F, and `CP A,(IX+3)` as BF rather
  than DD BE 03. Exit 0 and no diagnostic, on ordinary Zilog syntax that people
  write. The upper bound added in 0.3.44 only rejected three or more operands,
  which is why it did not reach this. A destination that is not the accumulator
  is now an error rather than a silent drop — for these five and for ADD/ADC/SBC
  too, since `ADD B,C` fell through to `ADD B` and dropped the C the same way.
  That last part breaks source that used to assemble: `ADD B,C` and `CP B,5`
  exited 0 under 0.3.43 and now stop the assembly.
- um80 assembler: `.Z80`/`.8080` mode no longer leaks across passes. The mode
  was set once in `__init__` and never reset, so the mode pass 1 ended in became
  pass 2's starting mode, and a `.Z80` anywhere in a file assembled the lines
  ABOVE it as Z80 on the second pass: `JP addr` silently became C3 instead of
  the 8080 F2 (jump if positive), and `CP n` a two-byte FE instead of the
  three-byte F4 (call if plus), which moves every label after it. Exit 0, no
  diagnostic. The mode now resets each pass exactly as the radix does, since a
  `.Z80`/`.8080` re-applies on every pass. This undercut the advice in 0.3.44's
  own error message: a user told to add a `.Z80` directive who put it at the
  bottom of the file silently changed the meaning of everything above it.
- Documentation: the three Microsoft manual links in README.md, the manual list
  in docs/index.md and the pointer in docs/project.txt all named
  `docs/external/m80.pdf` and its neighbours. Those PDFs have never been
  tracked in this repository or shipped in the sdist, so every one of those
  links was dead for anyone who did not already have a private copy of that
  directory; they now point at the retro_docs archive. The "From source"
  instructions in README.md also cloned `github.com/um80/um80_and_friends.git`,
  an organization that does not exist, so that copy-and-paste clone failed
  outright; it now names `avwohl`. No code changed for either.

## [0.3.44] - 2026-08-03

### Added
- README.md documents that 8080 is the default mode and that Z80 mnemonics need
  a `.Z80` directive, quotes the text of the new error below, and notes that
  `um80 -e .z80 file.mac` sets the mode from the command line without editing
  the source. The change below turns a silent operand drop into a hard error,
  and someone who hits that error otherwise has no way to learn that the mode
  is positional or that there is a route that does not involve editing every
  file. (The Related Projects list in the same file was separately rewritten in
  Simplified Technical English: wording only, same projects, same links.)
- docs/ISSUES.md #4 records a ulib80 defect found while measuring the blast
  radius of that change and NOT fixed here: `ulib80 -c lib.lib` writes a
  different byte stream on every run over the same unchanged `.rel` inputs,
  because the library writer iterates a `set` or `dict`; pinning
  `PYTHONHASHSEED` makes the output reproducible. The archive still links
  correctly, so nothing built from it is wrong, but a byte comparison cannot be
  used to tell whether a toolchain change altered a library — across the 0.3.44
  change every uc80 `.rel` module came out byte-identical while `libc.lib` and
  `runtime.lib` differed on every rebuild.

### Changed (deliberate divergence from MACRO-80 3.44)
- um80 assembler: An operand given to an instruction that takes none is now an
  ERROR, so nothing is written and the exit status is 1. It used to be a
  warning (or, for the conditional returns, no diagnostic at all) and the
  operand was thrown away, which silently assembled a different program:

  - `RET NZ` assembled as `C9`, an unconditional RET (Z80: `C0`).
  - `RLC B` assembled as `07`, RLC A (Z80: `CB 00`).
  - `RRC C` assembled as `0F`, RRC A (Z80: `CB 09`).
  - `RZ FOO` assembled as `C8` with no diagnostic at all.
  - `NOP 5` assembled as `00`.

  All 17 8080 no-operand mnemonics (NOP RLC RRC RAL RAR DAA CMA STC CMC HLT RET
  PCHL SPHL XCHG XTHL DI EI), all 8 conditional returns (RNZ RZ RNC RC RPO RPE
  RP RM), and the Z80-mode no-operand and ED-prefix no-operand mnemonics are
  covered. When the mnemonic and its operand spell a valid Z80 instruction
  (`RET cc`, `RLC r`, `RRC r`), the message names the `.Z80` directive, which is
  what makes um80 assemble Z80 mnemonics; for `RET cc` it also gives the 8080
  spelling (`RET NZ` is `RNZ`), and for `RLC r` and `RRC r`, which have no
  8080 spelling, it says that the 8080 rotate applies to A only.

  Genuine MACRO-80 3.44 instead flags these `Q` (questionable), emits the
  operand-less opcode and still writes the .REL; this is therefore a knowing
  break with M80 bit-compatibility, made because turning `RET NZ` into an
  unconditional `RET` is a silent miscompile. Measured blast radius is zero:
  the 14 original Microsoft MBASIC 8080 sources, the 98 uc80 library modules
  and every other `*.mac` outside `external/` assemble to byte-identical
  objects with no new diagnostics.

  8080 mode remains the default (M80 behavior), and the legitimate 8080
  readings of `JP`/`CP` (jump-if-positive, call-if-plus) are unchanged.

### Fixed
- um80 assembler: A Z80 ALU mnemonic with three or more operands is now an
  error. `ADD A,B,C` assembled as `ADD A` and dropped the rest.

## [0.3.43] - 2026-07-21

### Fixed
- um80 assembler: The two-operand Z80 ALU forms `ADD/ADC/SBC A,<expr>` no
  longer uppercase the immediate expression. Both operands are uppercased to
  match register names (`ADD HL,DE`, `ADC A,B`, ...), and the uppercased COPY
  of the immediate was fed back into expression evaluation, so `ADD A,'a'`
  assembled as `ADD A,'A'` (C6 41) and `ADD A,'a'-'A'` as `ADD A,0` (C6 00) -
  a tolower routine built on it was silently a no-op. Single-operand forms
  (`SUB 'a'`, `CP 'a'`) and all other mnemonics were unaffected, which is why
  the wrong bytes assembled without any diagnostic. Register matching remains
  case-insensitive. Found via a broken lowercase-filename export in the
  romwbw_emu W8 utility.

## [0.3.42] - 2026-06-13

A broad M80-compatibility audit. Every fix below was verified against the
genuine MACRO-80 / LINK-80 3.44 binaries running under cpmemu.

### Fixed
- um80 assembler: Expression operator precedence now matches M80. The unary
  operators (NOT, unary minus/plus, HIGH/LOW) were evaluated first, giving them
  the lowest precedence; they are now at their correct levels, so `-2+3`=1,
  `NOT 1 AND 2`=2, `3*-2 AND 0FFH`=0FAH, `HIGH 1234H + 1`=13H, `-1 GT 1`=0FFFFH,
  and `HIGH(1234H)+LOW(5678H)` parses correctly.
- um80 assembler: A two-character constant places the first character in the
  high byte (`'AB'`=0x4142), so `DW 'AB'` emits bytes `42 41`.
- um80 assembler: `LD A,I` / `LD A,R` now encode `ED 57` / `ED 5F` (were emitted
  as `LD A,0`).
- um80 assembler: Macro fixes — EXITM is ignored inside a false conditional
  branch (the IF/EXITM/ENDIF idiom); a user macro shadows a built-in
  instruction/pseudo-op of the same name; parameter, LOCAL and `%` substitution
  no longer corrupt quoted string literals; `IF NUL <param>` works with an
  omitted argument.
- um80 assembler: REPT/IRP/IRPC fixes — a directly nested repeat block is no
  longer dropped; `IRP X,<<1,2>,<3,4>>` iterates twice (not four times) and
  strips one bracket level per item; EXITM terminates a repeat expansion.
- um80 assembler: `.RADIX` evaluates its operand in decimal regardless of the
  current radix (so `.RADIX 16` works), and the radix resets each pass.
- um80 assembler: An unterminated conditional (missing ENDIF) is reported, and
  a duplicate ELSE for one conditional level is an error.
- um80 assembler: Cross-class symbol redefinition is rejected — a SET/DEFL/ASET
  symbol and an EQU/label symbol cannot redefine each other (multiply defined).
- ul80 linker: A multiply-defined PUBLIC global is now an error (was a warning),
  matching L80's `%Mult. Def. Global`.
- ul80 linker: Reworked segment placement so absolute (ASEG) code is emitted at
  its absolute address instead of being rebased to the relocatable load address
  (resolves docs/ISSUES.md #1). A module mixing CSEG and ASEG now keeps the CSEG
  relocatable while emitting the ASEG block at its ORG (previously the CSEG was
  silently dropped), and a module contributing only a COMMON block no longer
  has its bytes miscounted as program code. Verified against LINK-80 3.44.

## [0.3.41] - 2026-06-13

### Fixed
- um80 assembler: Fixed the DRI `!` multi-statement separator corrupting macro
  invocations. On a macro-call line, `!` is the M80 argument-quote operator
  (e.g. `head FOO,!!CF` passes the name `!CF`, and `!,` passes a literal comma),
  not a statement separator, so such lines are no longer split on `!`. Escaped
  commas in a macro argument list are also kept within their argument (issue #3).
- um80 assembler: Fixed `&`-concatenation of a macro parameter being
  case-sensitive, so a lowercase `&name` referencing parameter `name` left a
  stray `&` in the output instead of substituting the argument (issue #3).

### Removed
- Removed the stale standalone scripts under `src/` (um80, ul80, ulib80,
  ucref80, ud80, and the `um80_*opcodes`/`um80_relformat` helpers). They were a
  pre-package copy that had drifted months out of sync; the installed tools all
  run from the `um80/` package (see `pyproject.toml` entry points).

## [0.3.40] - 2026-04-09

### Fixed
- um80 assembler: Fixed `DEFS count,fill` ignoring the fill-value operand and
  emitting zero bytes instead of `count` bytes of the fill value (issue #2).

## [0.3.39] - 2026-04-09

### Fixed
- ul80 linker: Fixed ASEG `.COM` output including 256 leading null bytes when
  the source had `ASEG` followed by `ORG 0100H` (issue #2).

## [0.3.38] - 2026-04-08

### Added
- um80 assembler: Added `ASET` directive (M80-compatible alias for `SET`/`DEFL`).

### Fixed
- um80 assembler: Fixed `EQU` with forward references incorrectly triggering "multiply defined"
  error on pass 2 when the symbol value changed due to forward reference resolution.

## [0.3.37] - 2026-03-29

### Fixed
- ud80 disassembler: Fixed incorrect bit pattern comments for DCX and LDAX opcodes.
- ux80 translator: Fixed ALU mapping comments that incorrectly described output format.
- ucref80, ux80: Removed unreachable dead code (try/except around decode with errors='replace').

## [0.3.24] - 2025-12-31

### Fixed
- um80 assembler: Fixed ORG tracking to only apply to ASEG (absolute segment).
  ORG in CSEG/DSEG now correctly just sets the location counter without affecting
  segment origin. Fixes `org $-1` patterns in relocatable code that broke in 0.3.5.

## [0.3.20] - 2025-12-28

### Changed
- Added GitHub Actions workflow for automated PyPI publishing via trusted publishers.

## [0.3.19] - 2025-12-28

### Fixed
- ul80 linker: PRL/SPR output now defaults to origin 0 instead of 0x100.
  Previously, --prl incorrectly used the CP/M COM default origin, causing
  all addresses to be 0x100 too high in SPR files.

## [0.3.18] - 2025-12-28

### Fixed
- ul80 linker: Binary output files (.COM and .PRL) now padded to 128-byte
  CP/M record boundary. Fixes MP/M 2 .SPR file loading issues.

## [0.3.17] - 2025-12-21

### Fixed
- ul80 linker: Fixed segment buffer management when switching between segments
  (e.g., CSEG -> DSEG -> CSEG). Previously, returning to a segment could overwrite
  data from other segments. Now uses separate buffers per segment type.

### Added
- Test suite for DS and ORG directive combinations (`tests/test_ds_org.py`)
  covering segment switching, RST vector layouts, and external references.

## [0.3.16] - 2025-12-18

### Added
- ul80 linker: Predefined `__END__` symbol pointing to the first free byte after
  all linked segments (code + data + common blocks). Useful for dynamic memory
  allocation in CP/M programs.
- Test suite for `__END__` symbol (`tests/test_end_symbol.py`)

### Fixed
- ul80 linker: Fixed segment buffer offset calculation for external references
  in absolute-origin code (ORG directive with absolute address).

## [0.3.15] - 2024-12-16

### Fixed
- ul80 linker: Fixed segment buffer management to prevent SET_LOC to new segments
  from overwriting bytes from earlier segments. Chain following now correctly uses
  buffer offsets instead of segment-relative addresses.

## [0.3.14] - 2024-12-16 [YANKED]

Yanked due to missing `__version__` update. Use 0.3.15 instead.

## [0.3.13] - 2024-12-14

### Fixed
- Symbol case sensitivity: REL file reader now uppercases all symbols when
  reading, matching original Microsoft L80 behavior. The linker is now fully
  case-insensitive regardless of the source assembler.

### Added
- Test suite for case sensitivity handling (`tests/test_case_sensitivity.py`)

## [0.3.12] - 2024-12-14 [YANKED]

Yanked due to missing `__version__` update. Use 0.3.13 instead.

## [0.3.11] - 2024-11-26

### Added
- Library (.lib) file support in ul80 linker

## [0.3.10] - 2024-11-26

### Added
- MP/M .PRL (Page Relocatable) output format support in ul80

## [0.3.9] - 2024-11-26

### Fixed
- .SYM file output format for SID.COM/ZSID.COM debugger compatibility

## [0.3.8] - 2024-11-26

### Fixed
- REPT/IRP/IRPC directives inside macros
- `&` substitution operator in macros
- Angle bracket stripping in macro arguments

## [0.3.7] - 2024-11-26

### Fixed
- DC pseudo-op handling

## [0.3.6] - 2024-11-26

### Fixed
- Relocatable address emission with ORG directive

## [0.3.5] - 2024-11-26

### Fixed
- ORG to high addresses no longer outputs spurious zeros

## [0.3.4] - 2024-11-26

### Fixed
- LD indirect addressing with external references and segments
- LD SP parsing improvements

## [0.3.0] - 2024-11-26

### Added
- ux80: 8080 to Z80 assembly translator

## [0.2.4] - 2024-11-26

### Added
- Named labels in ud80 disassembler
- DC/DA string directives support
- Jump table detection and support

## [0.2.1] - 2024-11-26

### Fixed
- GitHub URLs in package metadata

## [0.2.0] - 2024-11-26

### Added
- ud80: 8080/Z80 disassembler for CP/M .COM files
- Z80 instruction set support in um80

## [0.1.0] - 2024-11-26

### Added
- Initial release
- um80: MACRO-80 compatible assembler
- ul80: LINK-80 compatible linker
- ulib80: LIB-80 compatible library manager
- ucref80: Cross-reference utility
