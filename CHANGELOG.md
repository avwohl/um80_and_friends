# Changelog

All notable changes to the um80 toolchain are documented here.

## [0.3.48] - 2026-09-24

Five defects found by building all of MP/M II V2.0 and V2.1 from Digital
Research's sources and comparing the result against DRI's binaries. Each has a
regression test that fails with its fix reverted.

### Changed
- ul80 linker: `--prl` now links a transient at 100H. MP/M loads a `.PRL` at
  `segment_bottom + 100H` but its relocator (NUCLEUS/CLI.ASM, `relocate`) adds
  only the segment's base *page* to the bytes the bitmap marks, so the extra
  page has to come from the link, exactly as for a `.COM`. It was linked at 0,
  which put every relocated address a page below the code: source-built MP/M
  utilities loaded, printed nothing and dropped the session. DRI's binaries
  state the convention — the highest relocatable word in `STAT.PRL` is its
  program length plus 100H. **A `.PRL` linked with `--prl` by an earlier
  release was wrong; relink it.**
- ul80 linker: system pages (`.SPR`, `.RSP`, `.BRS`), which MP/M loads at the
  segment base and which really are linked at 0, have their own switch,
  `--spr`.
- ul80 linker: in page-relocatable output a resolved reference to an absolute
  symbol below 100H — the BDOS entry at 0005H, the default FCB at 005CH, the
  DMA buffer at 0080H — is now marked for relocation, because under MP/M page
  zero belongs to the process's memory segment. DRI got the same effect by
  linking twice at different offsets (PLM_WORK/X0100.ASM and X0200.ASM) and
  letting GENMOD diff the results; DRI's `DIR.PRL` marks twelve `CALL 5`
  sites. An absolute symbol at or above 100H stays absolute.

### Added
- ul80 linker: `--extra HEX`, the memory a `.PRL` asks MP/M for beyond its
  image, for storage a PL/M program places at `.MEMORY`. Nothing in the object
  files says how much, so DRI named it at build time as GENMOD's third
  argument; its ASM, ED, PIP and SDIR reserve 1000H and RDT 1500H.
- um80 assembler: `--aseg` assembles a source written for DRI's MAC the way MAC
  does — absolute, so an `ORG` is an address rather than an offset in CSEG.
  MP/M II's assembler is seven such modules, each with its own `ORG`, which DRI
  assembled separately and concatenated as HEX; assembled as relocatable they
  were stacked end to end and `ASM.PRL` came out at 36971 bytes against DRI's
  8171. With `--aseg` it is 8176 bytes, and the `BOOT.HEX` it produces from
  `BOOT.ASM` is byte-identical to the one DRI's own `ASM.PRL` produces.

### Fixed
- um80 assembler: an offset subtracted from an external symbol kept its sign.
  `LXI H,PDTBL-34H` assembled to `PDTBL+34H` — the two branches that separate
  the constant from the symbol were swapped, so the constant to the right of a
  `-` was added and the one to the left negated. `SYM+n` and `n+SYM` were
  right, which is why it survived. `n-SYM` (a negated symbol) and an expression
  naming two externals cannot be carried in a `.REL` file and are now errors
  rather than wrong code. In MP/M II's CLI this put every process descriptor
  reference 68H bytes past the table, so a source-built system warm-booted
  instead of running any transient.
- um80 assembler: a label named after a mnemonic assembled to the opcode byte.
  An opcode name stands for its own byte (`DB MOV` is 40H), and um80 applied
  that before looking in the symbol table, so `CALL ADD` assembled to
  `CALL 0080H` (80H is `ADD A,B`) even where `ADD` was a defined procedure. A
  defined or external symbol now wins; the opcode byte remains for names that
  are not symbols. MP/M II's `STAT.PLM` declares `add: procedure`, and STAT
  executed its own command tail at 0080H and restarted, printing its drive
  line 1837 times.
- ul80 linker: `__END__` exported to another module was zero. A PL/M
  `AT (.MEMORY)` compiles to a public alias of `__END__`, which has to be
  registered before externals are resolved but has no value until every
  segment is placed; it is now recomputed once the bases are known. SDIR's
  hash table is declared that way in one module and used from another, and it
  cleared 256 bytes from address 0, BDOS vector included.

## [0.3.47] - 2026-09-23

### Documentation
- Backfilled the missing CHANGELOG entries for 0.3.25 through 0.3.36. The file
  ran from 0.3.37 straight back to 0.3.24, so twelve releases had no record at
  all — including 0.3.32, which carried the DSEG placement fix. That one had
  silently corrupted every multi-module link whose modules carry initialized
  data, and it is the sort of thing that needs to be findable afterwards: it
  surfaced months later as an MP/M II system image that was 1152 bytes short
  and would not boot. No code changes in this release.

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

## [0.3.36] - 2026-03-12

### Added
- ul80 linker: Predefined `__BSS_START` and `__BSS_END` symbols giving the
  bounds of the COMMON region, alongside the `__END__` symbol added in 0.3.16.
  A crt0 that zeroes uninitialized data before entering `main` needs both ends
  of that region and previously had no way to ask the linker for either.

### Fixed
- um80 assembler: An unnamed COMMON block (`COMMON //`, whose name is the empty
  string) was not recognized as a COMMON block at all. The location-counter
  getter and setter and the `seg_type` property all tested
  `if self.current_common:`, and Python treats `''` as false, so a blank COMMON
  — the form every C compiler's BSS uses — was assembled as though the block
  had never been opened: the bytes were counted against the enclosing segment
  and labeled with its segment type. The tests are now `is not None`.
- ul80 linker: With `--no-ds-zeros`, the DSEG output size still counted
  reserved (DS) bytes, so space merely reserved at the end of the data segment
  was written out as zero padding in the binary — exactly the bytes that option
  exists to leave out. Only initialized bytes (DB/DW) are counted now.

## [0.3.35] - 2026-03-11

### Fixed
- um80 assembler: External references are no longer threaded through a linked
  list embedded in the emitted code. Each reference stored the offset of the
  previous one in its own two bytes, with 0 as the end-of-chain marker, which
  is indistinguishable from a reference at offset 0 of a segment — a perfectly
  ordinary place for the first instruction of a module to be. The linker
  stopped walking there, so every earlier reference in that chain kept the raw
  chain link instead of the resolved address. The assembler now emits one
  CHAIN_EXTERNAL record per reference. Chains are also keyed by segment type,
  so a chain started in one segment can no longer run into another and patch
  bytes that belong to it.
- ul80 linker: A location fixed up while resolving an external reference could
  be relocated a second time in Phase 2, adding the segment base twice. The
  linker now records the locations it resolved externally and skips them.

## [0.3.34] - 2026-01-25

### Fixed
- ul80 linker: A reference from DSEG to a CSEG symbol — an initialized function
  pointer, `int (*f)(int) = &some_function;` — was placed using the code base
  rather than the data base. The relocation records carried only the target's
  segment type, not the referencing segment's, so the output offset was
  computed from `code_base` for a location that lives at `data_base`: the
  patched address was written into the wrong bytes of the image, and external
  chains anchored in DSEG were followed from the wrong buffer offset as well.
  Relocation records are now 3-tuples carrying the referencing segment type.

## [0.3.33] - 2026-01-24

### Added
- um80 assembler, ul80 linker: `EQU` accepts an external symbol plus an
  optional offset, and such an alias can itself be declared PUBLIC:

      EXTRN   ROUTINE
      PUBLIC  ROUTINE_ALT
      ROUTINE_ALT EQU ROUTINE+2

  The assembler emits uses of the alias as external-plus-offset references and
  writes an exported alias as `NEWNAME=EXTERNAL+N`; the linker defers those
  publics and resolves them before linking. z88dk libraries use this to publish
  alternate entry points a few bytes into an existing routine. Documented in
  README.md and docs/EXTENSIONS.md, with tests in `tests/test_ext_alias.py`.

## [0.3.32] - 2026-01-08

### Fixed
- ul80 linker: Initialized DSEG data is placed at the module's data base
  address instead of immediately after that module's own code. The linker had
  treated each module's CSEG and DSEG as one contiguous block and copied the
  whole buffer to `code_base`, so a module's initialized data landed directly
  on top of whatever was linked next — which, in a multi-module link, is the
  next module's code. Nothing reported it: the link succeeded, the file was
  written, and the image was wrong. Any link of more than one module where the
  modules carry initialized data was silently corrupted, and the corruption was
  worse the more modules there were.

  It was finally identified by size. MP/M II's XDOS.SPR is built from 19
  modules, nearly all of which use DSEG; ul80 produced an 8960-byte XDOS.SPR
  where DRI's own XDOS.SPR is 10112 bytes. The 1152 missing bytes were the
  overlap — data written over code that the output was then never sized to
  hold. CSEG bytes now go to `code_base`, initialized DSEG bytes to
  `data_base`, and the output buffer is sized to cover both regions.
- tests: `tests/test_case_sensitivity.py` expected symbols to be truncated to
  eight characters, but `RELWriter` defaults to `truncate_symbols=False` and
  keeps the full name. The expectations were wrong, not the writer; no
  behavior changed.

## [0.3.31] - 2026-01-07

### Fixed
- um80 assembler: `EX AF,AF'` no longer swallows the rest of the line. The
  trailing apostrophe was read as the start of a string literal, both when
  stripping comments and when splitting operands, so everything after it —
  including the comment and any following statement — was absorbed into an
  unterminated string. An apostrophe directly after an alphanumeric character
  is now part of the register name, not a quote.
- um80 assembler: The LOCAL symbol counter was not reset between passes, so the
  generated `??NNNN` names drifted: a symbol defined as `??0000` during pass 1
  was referenced under a different number in pass 2. The counter is now reset
  at the start of each pass-1 iteration and again for pass 2, so a LOCAL symbol
  keeps one name throughout.

## [0.3.30] - 2026-01-07

### Fixed
- um80 assembler: The `-e`/`--execute` and `--pre` options added in 0.3.29
  reached the installed tool. That release had added them only to `src/um80`, a
  standalone copy of the assembler that nothing runs — the `um80` entry point
  in pyproject.toml names `um80.um80:main` — so an installed 0.3.29 still
  rejected both options as unrecognized arguments. The same code is now in
  `um80/um80.py`. (The stale `src/` copies were removed outright in 0.3.41.)

## [0.3.29] - 2026-01-07

### Added
- um80 assembler: `-e`/`--execute CODE` assembles a line of inline source ahead
  of the main file, and `--pre FILE` includes a whole file ahead of it. Both
  may be repeated and are processed in the order given, and `-e` accepts the
  DRI `!` statement separator. This is how a source file's CPU mode or a
  conditional-assembly symbol can be set from the command line without editing
  the file — `um80 -e .z80 file.mac`. Note that in this release the options
  existed only in the unused `src/um80` script; see 0.3.30.

## [0.3.28] - 2026-01-06

### Fixed
- ul80 linker: External references resolved to DSEG and COMMON symbols are now
  recorded in the PRL relocation bitmap as well. 0.3.27 marked only targets in
  CSEG, so a cross-module pointer into another module's data segment or a
  COMMON block stayed at its link-time address when MP/M loaded the .PRL or
  .SPR anywhere else.

## [0.3.27] - 2026-01-06

### Fixed
- ul80 linker: Addresses patched in while resolving an external reference are
  included in the PRL relocation bitmap. The bitmap was built only from the
  relocations the linker applied from a module's own relocation records, so an
  EXTRN resolved to a symbol in another module — every cross-module call or
  jump — was written as a link-time address and never relocated when the image
  was loaded at its real page. A single-module .PRL was correct, which is why
  this survived as long as it did.

## [0.3.26] - 2026-01-06

### Fixed
- `__version__` is read from the installed package metadata instead of being a
  hardcoded literal in `um80/__init__.py`. It had to be edited by hand in step
  with pyproject.toml and regularly was not: 0.3.12 and 0.3.14 were both yanked
  for exactly this, and every tool in 0.3.25 reported itself as 0.3.24. There
  is now one place to change.

## [0.3.25] - 2026-01-05

### Fixed
- um80 assembler: `$` evaluated one byte too high in the 8080 instructions that
  take an address operand (JMP, the conditional jumps, CALL, the conditional
  calls, LXI, LDA and their kin). The opcode byte was emitted before the
  operand expression was parsed, so `$` saw the location counter already
  advanced past it: `JNZ $-5H` assembled a target one byte beyond the one
  written. The expression is now parsed first and the opcode emitted after.
- um80 assembler: A CSEG/DSEG/ASEG directive now emits a SET_LOC record, so the
  linker switches output buffers where the source does. Without it the bytes
  after a segment switch were accumulated into the previous segment's buffer.
- ul80 linker: DS zero fill was applied only when the location counter advanced
  within the current segment, so space reserved immediately after a switch to
  another segment was not filled.

### Changed
- ul80 linker: DS directives now emit zeros by default; `--no-ds-zeros`
  restores the old behavior of treating reserved space as BSS. PRL and SPR
  images must be contiguous, and space reserved at the end of a segment was
  simply absent from the file — which is what prevented MPM.SYS from being
  built with these tools.

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
