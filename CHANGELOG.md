# Changelog

All notable changes to the um80 toolchain are documented here.

## [0.3.14] - 2024-12-16

### Fixed
- ul80 linker: Fixed segment buffer management to prevent SET_LOC to new segments
  from overwriting bytes from earlier segments. Chain following now correctly uses
  buffer offsets instead of segment-relative addresses.

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
