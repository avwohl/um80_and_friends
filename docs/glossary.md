# Glossary

This glossary gives one name to each item in the um80_and_friends project.
It also lists the technical verbs that the project registers.
The documents of the project are written in the style of ASD-STE100
Simplified Technical English.
This file is not a copy of the STE dictionary.

Two rules decide the content of this file:

- Rule 1.11: one item has one name. Use the name in the Term column.
  Do not use a name from the "Do not use" column.
- Rule 1.12: a technical verb that is not in the STE dictionary is
  registered here. Use a registered verb only in the meaning that this file gives.

Look up a word here before you write a new document or change an old one.
If the word is not here, add the word to this file in the same change.
[writing.md](writing.md) gives the other rules for the documents.

## Naming rules

- Write the full name of a tool once in each document: for example
  "MACRO-80 (M80)". After that, write only the short name.
  In a man page, write the full name in the NAME section and the short name after it.
- M80, L80, LIB-80 and CREF name the Microsoft programs. um80, ul80, ulib80 and
  ucref80 name the programs of this project. Never use one name for both.
- Write a version only when the version matters: "M80 3.44".
- Write a program name in lowercase in code font: `um80`, `ul80`.
- A file extension in running text has capital letters for CP/M file types:
  .REL, .COM, .MAC, .PRN, .LIB, .SYM, .HEX, .PRL, .SPR. The capital letters
  name the file type, as the Microsoft manuals do. The tools write lowercase
  names (`prog.rel`, `prog.com`, `prog.sym`, `prog.hex`, `prog.bin`: um80.py and
  ul80.py do this), so a file name in an example stays lowercase.
  The extensions of the debug files and of the ELF file are in lowercase: .dbm,
  .dbg, .elf.
  A file name in a code span keeps its case.
- A real file name (`output.rel`, `prog.dbg`) is in code font and has the
  case that the command line has. A tool does not change the case that you type.
- In a number, the suffix H is in capital letters: 100H, 0FFFFH. An option
  that takes hexadecimal digits says "in hexadecimal" in the help text. The
  option value has no suffix.
- Write "option" for an item on the command line. Do not write "switch" or "flag"
  for an option. "flag" is a verb for an error code (see the verb table). This rule is also for the options of M80 and L80, for example
  "the L80 option /D". The word "switch" stays in its other meanings: the C
  statement `switch`, "a switch to another segment", "a task switch". The word
  noun "flag" stays for a CPU flag bit.
- Use American spelling: honor, behavior, labeled, recognized, neighbor.

## Technical nouns

### Programs and projects

Term | Meaning | Do not use
--- | --- | ---
MACRO-80, M80 | The Microsoft assembler, version 3.44. M80 is the program name. | genuine M80, real M80, original M80, the Microsoft assembler, MACRO80
LINK-80, L80 | The Microsoft linker, version 3.44. | genuine L80, original linker, LINK80
LIB-80 | The Microsoft library manager. | LIB80
CREF | The Microsoft cross-reference program. | CREF80
um80 | The assembler of this project. It follows M80. | the assembler (when you mean um80), MACRO-80 compatible assembler (after the first use). "Assembler" alone is allowed when the text is about assemblers in general
ul80 | The linker of this project. It follows L80. | the linker (when you mean ul80)
ulib80 | The library manager of this project. | LIB80 (docs/index.md lines 14, 185, 187 write "LIB80"; the Microsoft program is "LIB-80")
ucref80 | The cross-reference program of this project. | CREF80 (docs/index.md line 15 writes "CREF80"; the Microsoft program is "CREF")
ud80 | The disassembler of this project. | the disassembler (when you mean ud80)
ux80 | The program that translates 8080 source files to Z80 source files. | converter, source-to-source translator
udb80 | The source-level debugger of this project. | the debugger (when you mean udb80). "Debugger" alone is allowed when the text is about udb80 and GDB together.
dbg2elf | The program that writes an ELF file from a DBG file. | the ELF writer
um80_and_friends | The project and the repository. | um80 (for the whole project), suite
the um80 package | The package that you install with `pip install um80`. It has the version number (0.4.3 and so on). | um80 0.4.0 (when you mean the package: write "package um80 0.4.0")
tool | One program of the project (um80, ul80 and so on). | utility
toolchain | All the tools of the project together. | suite
MAC | The Digital Research macro assembler (MAC 2.0). | DRI's MAC, MAC (when you mean the .MAC file)
RMAC | The Digital Research relocatable macro assembler (RMAC 1.1). | DRI's RMAC
ASM | The Digital Research basic CP/M assembler. | -
DRI | Digital Research, Inc. Write "Digital Research (DRI)" at the first use. | -
the --dri option | The um80 option that reads the source as MAC and RMAC read it. | DRI mode, DRI extensions (for this option), DRI-compatible mode
cpmemu | The CP/M emulator of the project cpmemu. It runs M80, L80 and the programs that you build. Write "cpmemu". Write "CP/M emulator" only at the first use in a document, with the name cpmemu. | a CP/M emulator (when you mean cpmemu), cpm (the command in an example must be `cpmemu`)
romwbw_emu | The RomWBW emulator that udb80 can use. | -
altair_emu | The Altair emulator that docs/ISSUES.md names. It is not in this repository. | -
emulator | Allowed alone only when the text is about any emulator, or after the text names which one. | -
GDB | The GNU debugger. Always in capital letters. | gdb (as a name; `gdb` is only the command)
GDB stub | The part of an emulator that talks the GDB remote protocol. Write "GDB stub" at the first use in a document. After that, "the stub" is the short name (rule 1.9), but only when the document has no other stub. | GDB server, stub for any other meaning
mbasic2025 | The repository of the MBASIC sources. | mbasic_521 (that is a directory name: code font)
MBASIC 5.21 | The Microsoft BASIC program that mbasic2025 builds. | MBASIC 5.2 (a different source: do not write it for 5.21)
four-way link test | The test that links the same program four ways: M80 and L80, M80 and ul80, um80 and L80, um80 and ul80. | four-way, fourway, mix, mixed build

### Files and formats

Term | Meaning | Do not use
--- | --- | ---
source file | A text file that um80 reads. Extension .MAC (or .ASM). | assembly file, assembly source, sources (for "source files"), module (for a source file)
REL file | The file that um80 or M80 writes and that ul80 or L80 reads. Extension .REL. The Microsoft manuals and the format name say "REL". In the name of a RMAC output file, write "REL file" too. | object, object file, .rel file, relocatable object, object module, obj, "um80's objects" (write "the REL files of um80")
REL format | The format of a REL file. | REL (alone), Microsoft object format
module | One unit in a REL file or in a library. A REL file can have more than one module. | object (for the unit), routine (for the unit)
library file | A file of REL modules that ulib80 or LIB-80 writes. Extension .LIB. | archive, ULIB file. "Library" alone is the short name: allowed when the text is about libraries in general, or when the document has said "library file" before and the meaning is clear.
ULIB format | The format of a library file that ulib80 writes (container version 2). It is not the format of LIB-80. | custom library format
macro library | A source file that MACLIB reads. Extension .LIB. | MACLIB library (as a name for the file), library (alone)
include file | A source file that INCLUDE reads. | included file
COM file | The CP/M program file that ul80 writes. Extension .COM. | binary, executable, .com file (in running text), program file (except in the debug manuals: there it is the COM file)
image | The bytes that the linker writes to the output file, as they are in memory. | binary, raw image (use "BIN file" for the file)
output file | Any file that a tool writes. Name the type when the type matters. | -
BIN file | The raw image that `ul80 --bin` writes. Extension .bin. | raw binary, raw image file
HEX file | The Intel HEX text file that `ul80 -x` writes. Extension .HEX. | hex file, hex output
hexadecimal | A number in base 16. | hex (as a noun for the radix)
PRL file | The MP/M page-relocatable file for a transient program. Extension .PRL. | transient .PRL
SPR file | The MP/M system page-relocatable file. Extension .SPR (also .RSP and .BRS). | system page file
relocation bitmap | The bitmap at the start of a PRL file or SPR file. It marks the bytes that MP/M relocates. | page bitmap, bitmap (alone)
listing file | The text file that um80 writes with the option -l. Extension .PRN. Write "the listing" only for the text inside a listing file ("the error code in the listing"). | assembly listing, PRN file (use only for the extension)
cross-reference listing | The output of ucref80. | listing, CREF listing
symbol file | The file that ul80 writes with -s or -S. Extension .SYM. | SYM file, symbol table (that is the table inside the program)
EQU file | The file that ul80 writes with `--equ-file`. It has lines of the form NAME EQU value. | symbol file (for this file)
debug information | All the data that the debug tools use. | debug info, debug data
DBM file | The file that um80 writes with `--debug-info`. It has the debug information of one module. Extension .dbm. | module debug file, debug map, .dbm file (in running text)
DBG file | The file that ul80 writes with `--debug-info`. It has the debug information of the linked program. Extension .dbg. | program debug file, debug file, linked debug file, .dbg file (in running text)
ELF file | The file that dbg2elf writes. It has DWARF data. | ELF32 file, DWARF file
marker | A comment line in a source file that starts with `;#`. | record (for a marker), directive
configuration file | A file that holds settings for cpmemu. | config
man page | A manual page in the directory docs/man. | manual (for a man page)

### Names, symbols and the linker

Term | Meaning | Do not use
--- | --- | ---
name | The text of a symbol. | identifier
symbol | A name and its value in the symbol table. | -
label | A symbol that marks an address. It is followed by a colon, or it is the first word of a line (see the section "A label needs a colon" of compatibility.md). | -
public symbol | A symbol that a module makes available to other modules. A PUBLIC directive or a `::` label declares the symbol. | global (for this meaning), exported symbol, entry point, export. "Global" stays only in: a quoted L80 message ("Mult. Def. Global"), the name of the option --globals, the field `global` of the DBG file (value 1 for a public symbol), and the two meanings below.
public label | A label that is a public symbol. The DBG file marks such a label with the field `global` (value 1). | global label
global variable | A C variable that has a fixed address and external linkage (uc80, debug files). In no other meaning. | global (alone)
external symbol | A symbol that a module takes from another module. An EXTRN directive or a name with the suffix `##` declares the symbol. | external (as a noun), import, external reference (use only for one use of the symbol)
PUBLIC, EXTRN, `##` | The directives and the suffix. Always in code font. | -
alias | An external symbol plus an offset, that an EQU defines. | external alias
entry point | The address where ud80 starts to trace code (option -e). In no other meaning. The man pages and the docs/tools.md use "entry point" in two more meanings: the END operand (write "start address") and a label inside a routine that code jumps to (write "alternate start address of a routine"). | start address (for the END operand)
start address | The address in the operand of END. | entry point
link item | One item in a REL file. Microsoft names the 16 types "special link items" 0 to 15, and special link item 4 holds "extension link items" (A, B, C kinds). | record, relocation record
special link item | A link item with a number from 0 to 15. Write "special link item 12" at the first use in a section. After that, "special item 12" or "item 12" is the short name (rule 1.9), when no IRP item is near. | -
extension link item | The special link item 4. It has an expression that the linker evaluates. Write "extension link item" at the first use in a section. After that, "extension item" is the short name. | extension value. The Microsoft names "entry symbol" (special link item 0) and "define entry point" (special link item 7) are quoted only in a statement about the Microsoft documents. For item 0 write "the name of a public symbol, for library search". For item 7 write "the public symbol definition".
extension kind | The kind A, B or C inside an extension link item. | item A, kind (alone)
field | A part of a link item. Write "A-field" and "B-field". | -
link-time expression | An expression that the linker evaluates. | postfix program, extension value
placeholder | The bytes in the code that the linker replaces with the final value. | placeholder bytes, zero placeholder
reference chain | The list of the references to one external symbol. The list is in the code bytes. After the first use in a section, "the chain" is the short name (rule 1.9). "Call chain" and "return chain" are different things: use "backtrace" for these. | external chain, linked list
chain head | The first entry of a reference chain. | head of a chain
chain entry | One entry of a reference chain. | chain link, link (for an entry)
multiply defined symbol | A public symbol that more than one module defines. The L80 message says "Global". | duplicate name, global defined twice
name cut | The option -t cuts a name to 6 characters in the REL file. Write "cuts the name to 6 characters" ("cut" is an approved STE verb. The option name stays `--truncate`.). | shorten, 6-char, 8-char
REL name length | See the table "Name lengths" below. | -

### Segments, addresses and memory

Term | Meaning | Do not use
--- | --- | ---
code segment | The segment of the directive CSEG. | program segment, program relative (except as the name of a relocation type), program area
data segment | The segment of the directive DSEG. | data area, data relative (except as the name of a relocation type)
absolute segment | The segment of the directive ASEG. | absolute code (use for the code in it), absolute area
COMMON block | A named or unnamed block of the directive COMMON. | common (alone), blank COMMON, BSS (except in the symbol names `__BSS_START` and `__BSS_END`; write "COMMON block (the BSS)" at the first use)
segment | A code segment, a data segment, an absolute segment or a COMMON block. | area, region
location counter | The assembler counter for the current address. Its symbol is `$`. | location (alone), current location, PC (PC is only the CPU register)
offset | The distance from the start of a segment. | -
address | A number that names a byte in memory. In a linked program it is a final value. | -
origin | The address of the first byte of the image (option -p, directive ORG). | program base, link base, load address (these are different: see the next rows)
load address | The address where CP/M or a ROM programmer puts the bytes. | origin
run address | The address where the CPU executes the bytes (directive .PHASE). | -
DS area | The bytes that a DS directive reserves. | hole, gap (a gap is the space between two segments in the image)
fill byte | The value of the bytes in a gap and in the padding (option --fill). | -
padding | The bytes that ul80 adds at the end of a COM file to make a whole 128-byte CP/M record. | -
record | A unit of 128 bytes in CP/M. "Record" alone has this meaning only. With a modifier it names a registered item: "routine record", "frame record", "inline record", "variable record", "HEX record" (one line of a HEX file). Do not use for a link item, a marker or a REL special link item ("M record" in the mbasic2025 text is a different thing). | sector, block (these are different units)
program | The code that you build for CP/M and that the CPU runs. | tool (for um80 and so on)
CPU mode | The mode `.8080` or `.Z80` of um80. Write "8080 mode" or "Z80 mode". | processor mode, Z80 mode (alone, when you mean the option)
program counter (PC) | The CPU register. | location counter

### Source language and macros

Term | Meaning | Do not use
--- | --- | ---
statement | One instruction, directive or macro call, with its label. | line (when the meaning is statement), operation
instruction | A machine instruction of the 8080 or the Z80. | opcode (an opcode is only the byte value), mnemonic (for the instruction)
mnemonic | The name of an instruction. | -
directive | An assembler command, for example ORG. | pseudo-op, dot-directive (write "directive that starts with a dot")
first word of a statement | The first token of a statement that is not a label: an instruction name, a directive name or a macro name. The heading "The first word of a statement" in EXTENSIONS.md uses this term. | keyword (as a name for this item: "keyword" is the BASIC keyword in mbasic2025.md and "a `!` followed by a keyword"), operation
BASIC keyword | A word of MBASIC such as PRINT. It is in the mbasic2025 documents only. | keyword (alone)
token | A piece of text that the parser reads. | word (for text)
word | A 16-bit value of the CPU or of the REL format ("a relocatable word"). In other meanings the word "word" is the ordinary English noun. | token
operand | The value of an instruction or a directive. | -
operator | HIGH, MOD, + and so on. | -
macro call | The line that uses a macro. | macro invocation, invocation
parameter | A name in the line of the MACRO definition. | formal, param
argument | A value in a macro call. | actual
macro body | The text between the MACRO line and the ENDM line. | body (alone), block
expansion | The text that one macro call or one repetition produces. | macro expansion (use only when it is not clear)
repetition | One pass of a REPT, IRP or IRPC block. | iteration, round
IRP list | The list in the operands of an IRP. | list operand
IRP item | One part of an IRP list. | element, item (alone)
statement separator `!` | The character `!` that ends a statement (MAC, RMAC and the --dri option). | multi-statement character
quote character `!` | The character `!` that makes the next character literal (M80). Always say which `!` you mean. | -
pass 1, pass 2 | The two passes of the assembler. | pass-1 (as an adjective: write "of pass 1")
error code | The one-letter code that M80, MAC, RMAC and um80 write in the listing (A, D, E, M, N, O, P, Q, R, S, U, V and others). The verb is "flag" (see the verb table). | flag (as a noun), error flag, error letter
error | A fault that makes the tool stop or set the exit status 1. | -
warning | A message with which the tool continues and writes the output. | -
message | The text that a tool writes. A message can be an error or a warning. | diagnostic
exit status | The number that a tool gives to the shell. | return code, exit code
8080 code, Z80 code | Source text for the 8080 or the Z80. Always in this order. | Z80/8080

### Debugger terms

Term | Meaning | Do not use
--- | --- | ---
routine | A part of the code from a label to the next label, or as a `;#func` marker gives. | function (use only for a C function), subroutine, subprogram
routine record | The `;#func` marker and the data that it gives. | func record, frame record (see the next row)
inline record | The `;#inline` marker and the data that it gives. Its DWARF form is `DW_TAG_inlined_subroutine`. | -
variable record | The `;#var` marker and the data that it gives. | -
frame record | The frame data of a routine in the DBG file (the fields frame, pops, ixbegin and ixend). | routine record
IX frame | A stack frame whose base is in the register IX. | frame in IX
frame base | The IX value in a routine with an IX frame. | base, frame id
backtrace | The list of the calling routines. | call chain, chain of calls
frame | One entry of a backtrace, as GDB says it: the command `frame`, "up", "down", "the selected frame", "the innermost frame". GDB uses "frame" in this meaning. | backtrace entry, stack frame (write "IX frame" for an IX frame). "Frame" is not the "frame record" (data in the DBG file) and not the "IX frame"
shadow call stack | The list of return addresses that the GDB stub keeps. | shadow stack
unwind method | One of three ways in which udb80 finds a frame: shadow, frame or guess. The tag in the udb80 output is `[shadow]`, `[frame]` or `[guess]`. The command `bt shadow` and `bt frame` select the method. | source (for the way), records (that is the mode of the Python unwinder, next row)
Python unwinder | The script `udb80_unwind.py`. Its mode is `auto` or `records` (the command `udb80-unwind-mode`): this is not an unwind method of udb80. After the first use, "the unwinder" is the short name in docs/gdb.md and docs/frame_records.md. | walker
GDB unwinder | The unwinder that GDB has for the Z80. | built-in unwinder
step point | An address where a step stops. | statement (when the meaning is "step point")
line group | The lines of one address. | group, merged group, position group
source position | A file name and a line number. | position (alone)
code position | A segment and an offset. | position (alone)
source level | The lines that the markers `;#line` name (C, BASIC and so on). | -
assembler level | The lines of the .MAC file. | assembly level, asm level
outer level | The lines that outer=G:M names. | third level, level c
program file | The COM file (or other file) that udb80 or dbg2elf reads. Use only in the debug manuals. | -
memory dump file | The file that holds the memory of the program (for example `memory.bin`). | memory image, guest memory
live test | A test that needs cpmemu or GDB. | -
static test | A test that needs no cpmemu and no GDB. | -
measurement | A recorded result of a test or a probe. | -

### Name lengths

This table is the single source for the name-length rule. The documents must
not give a different number. The values come from measurements with M80 3.44
and L80 3.44 (issue #6). docs/EXTENSIONS.md gives the details.

Item | Value
--- | ---
Characters that the original REL format encodes in a B-field (a 3-bit length, 0 means 8) | 8
Characters that M80 keeps in its symbol table | 16
Characters that M80 writes for a PUBLIC or external name in the REL file | 6
Longest name that L80 reads | 7 (6 for an external in a link-time expression)
Characters that the REL format allows with the extended B-field | 255
Characters that um80 writes without the option -t | the whole name
Characters that um80 writes with the option -t | 6

## Registered technical verbs

These verbs are registered under category 2c of the skill (rule 1.12). Use each
verb only in the meaning that the table gives. A noun that has the same
spelling is in the Notes column.

Verb | Meaning in this project | Notes
--- | --- | ---
assemble | A tool translates source text to REL bytes or to machine bytes. The STE dictionary has "assemble" in the meaning "put together": use this verb only in the translation meaning. | The source does not "assemble": write "um80 assembles the source". Do not write "assembles as" for "treats as": write "assembles as DB" only when um80 writes the bytes of a DB.
disassemble | ud80 or udb80 translates bytes to instructions. | Noun: "the disassembly".
link | ul80 or L80 combines REL files into one image. | Verb only. Do not use "link" as a noun ("the link"). Write "the link step", "when ul80 links the program" or "the linked program". Do not use "link" for an entry of a chain (write "chain entry"). "link-time", "link step" and "link item" are modifiers and are allowed.
load | A tool or CP/M puts bytes at an address. | "load address" is a modifier and is allowed. A byte that is "loaded over" another byte: write "written to the same address".
relocate | The linker or MP/M adds a segment base or a page number to an address. | "relocatable" and "relocation bitmap" are allowed.
resolve | The linker connects an external symbol to its public symbol. | Do not use for "find the value of an expression": write "evaluate".
evaluate | The linker or the assembler calculates the value of an expression. | "calculate" is also correct. Do not use "compute" or "miscompute". For a wrong value write "gives a wrong value".
expand | um80 replaces a macro call with the macro body. | Noun: "expansion" (see the noun table). Do not use "go round" or "iterate": write "repeat".
repeat | A REPT, IRP or IRPC block produces its body again. | Not an STE-approved word in the skill's list: registered here.
place | ul80 gives an address to a segment. | "put" is also correct. Do not use "allocate", "lay out" or "arrange".
promote | um80 changes a JR or DJNZ that is out of range to a JP. | Use in this meaning only.
trace | ud80 follows the flow of control from an entry point. | Do not use for the output of a debugger.
translate | ux80 changes an 8080 source file to a Z80 source file. | Do not use "convert".
parse | um80 reads source text and decides what the text means. | Use where the text is about the parser. In other places "read" is the plain verb and is correct: "um80 reads `A$B` as MAC reads it".
read | A tool opens a file, reads bytes from a file or memory, or reads source text. | Do not use "reads on": write "continues to read".
write | A tool puts bytes or text in a file or on the screen. | Use "write" in place of "emit", "generate", "produce", "create" and "output" (as a verb).
include | A tool reads another source file at that place (INCLUDE, MACLIB, option --pre). | Do not use "include" for "contain": write "has".
quote | M80 reads the next character as a literal when the quote character `!` is before the character. | Noun: "quote character". Use only for the quote character `!`.
report | A tool writes an error or a warning message. | -
flag | M80, MAC, RMAC or um80 marks a statement with an error code in the listing: "M80 flags the line `Q`", "MAC flags it `S`". | Verb in this meaning only. As a noun, "flag" is a CPU flag bit only (for example the carry flag). Do not use the noun "flag" for an error code or for an option.
warn | A tool writes a warning and continues. | Use "writes a warning". Do not use "without a word": write "without a message".
mark | A tool sets a bit in a relocation bitmap, or puts a character in the listing. | Noun: "marker" is a separate noun (see the noun table).
pad | ul80 adds padding bytes at the end of a file. | Noun: "padding".
fill | ul80 sets the bytes of a gap to the fill byte. | Noun: "fill byte".
merge | ul80 combines the types or the rows of more than one module. | -
unwind | The debugger finds the calling routines from the stack. | -
step | udb80 or GDB runs to the next step point. | The commands `step`, `next` and `finish` are in code font.
inline | uc80 puts the body of a routine in the place of a call. | Use only for the compiler.
build | A script runs the assemble and link steps (and the other steps) that make a program. | Verb only. Do not use "build" as a noun: write "the result of the build" or name the file. "build script" and "build directory" are allowed as modifiers.
run | A user, a script or an emulator makes a program, a command or a test operate: "run the tests", "cpmemu runs M80". | Verb only. Do not use "run" as a noun ("a run of ul80"): write "each time you start ul80" or "when ul80 links the program". "run address" (a registered noun), the debugger commands `run` and `continue` and the option --run are names and stay.
start | A user or a tool begins a program or a process. | -
test | - | Noun only. Write "do a test of um80". "test suite" and "regression test" are nouns.
dump | - | Noun only: "a dump of memory", "bt-dump" (command name).
patch | - | Noun only: "a patch module". Write "apply a patch".
set | The directive SET, a bit that is set, or a value that a user sets. | Write the directive SET in code font. Do not use "set-location": write "set-location item".
emit | - | Not allowed. Use "write".

## Words to avoid

Only words that occur in the current documents are in this list.

Avoid | Use
--- | ---
genuine, real, original (for M80, L80 and LIB-80) | M80, L80, LIB-80 (or "the Microsoft M80" at a contrast)
without a word, silently | with no message
goes round, go round, iterates | repeats
goes on, go on, carries on, reads on | continues
leaves out, left out, drops, swallows | ignores, does not assemble, deletes (say which)
takes X for Y, took X for Y | treats X as Y, reads X as Y (for source text: parses X as Y)
beside (a file), next to, stands next to | in the same directory as
in front of | before
look for, looks for | search for
look up, look at | find, read
in force | active
stale | out of date, does not match
garbage | wrong, not correct
hang, crash | does not end, stops with an error
come out, comes out, goes out as | is, is written as
turn into, turn on, turn off | change to, enable, disable
honour | follow, obey (honor is American spelling, but follow is plain)
miscompile, miscompute, undercount | gives a wrong value, gives a wrong count
pinned, pins | records, checks against a fixed value
blast radius | the set of files that the change affects
release gate | release test
walker | frame scanner (or the registered term Python unwinder)
guest memory | emulated memory
e.g., i.e., etc., vs. | for example, that is, name the items, compared with
upper or lower case (as a noun) | letter case
switch (option) | option
flag (as a noun for an option or an error) | option, error code
support, supports | reads, writes, accepts
emit | write
generate, produce, create, output (as a verb) | write
execute (for um80 -e) | process (or "assemble")
simply, just, easily | delete
the rest | the remaining text
Latin abbreviations | see "e.g." above
contractions (don't, isn't) | do not, is not

## Abbreviations

Write the expansion at the first use in a document, unless the abbreviation is in
the table "Programs and projects" or is an instruction name in code font.

Abbreviation | Expansion
--- | ---
8080 | Intel 8080 CPU
Z80 | Zilog Z80 CPU
ASCII | American Standard Code for Information Interchange
ASEG, CSEG, DSEG | absolute segment, code segment, data segment
BDOS | Basic Disk Operating System
BIOS | Basic Input/Output System
BSS | block started by symbol (the uninitialized data)
CCP | Console Command Processor
CFA | canonical frame address
CI | continuous integration
COM | CP/M command file
CP/M | Control Program for Microcomputers
CPU | central processing unit
CR, LF | carriage return, line feed
DBG, DBM | the debug files (see the noun table)
DMA | direct memory access (in CP/M: the disk transfer address)
DRI | Digital Research, Inc.
DWARF | the debug data format of ELF (a name, not an acronym)
ELF | Executable and Linkable Format
FCB | file control block
GDB | GNU Debugger
HEX | Intel HEX file format
IM 1 | interrupt mode 1 of the Z80
IX, IY | index registers of the Z80
JSON | JavaScript Object Notation
LIB | library file extension
MAC, RMAC, ASM | the Digital Research assemblers (see the noun table)
MP/M | Multi-Programming Monitor Control Program (the multi-user CP/M)
NMI | non-maskable interrupt
PC | program counter
PRL | page relocatable (MP/M)
PRN | listing file extension
PSW | program status word (the register pair A and the flags)
RAM, ROM | random-access memory, read-only memory
REL | relocatable (the file type and the format)
RSP, BRS | resident system process, banked resident system process (MP/M)
SHA-256 | Secure Hash Algorithm with 256 bits
SP | stack pointer
SPR | system page relocatable (MP/M)
SYM | symbol file extension
uc80, uplm80, uada80 | the compilers of the family of this project (C, PL/M-80, Ada)
