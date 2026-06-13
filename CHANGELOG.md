# Changelog

All notable changes to the um80 toolchain are documented here.

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
