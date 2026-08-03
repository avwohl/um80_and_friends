# Open Issues

## 1. REL Format: Absolute ORG Representation

**Status:** Resolved (0.3.42) — the linker now places ASEG (absolute) segments
at their absolute address and never relocates them, verified against LINK-80
3.44. A module may mix relocatable CSEG with an absolute ASEG block (e.g. an
interrupt/RST vector) and each is placed correctly. The relocatable-CSEG-with-
`ORG` + `-p` approach still works as before for code like `cpm22.asm`.
**Component:** um80 assembler / ul80 linker

### Problem

When assembling code with `ORG <absolute_address>` in CSEG (the default code segment), there's ambiguity about how addresses should be represented in the .REL file:

**Current behavior:**
- `ORG 0xE000` in CSEG sets location counter to absolute address
- Labels (e.g., COMMAND at 0xE35C) are emitted as PROGRAM_REL
- Assembler now subtracts ORG (0xE000) to get offset (0x035C)
- Linker adds code_base (-p option) to relocate

**Alternative approach - ASEG:**
- Code in ASEG uses `ADDR_ABSOLUTE` (type 0) for all addresses
- Linker doesn't relocate absolute addresses
- SET_LOC would be `(0, 0xE000)` and addresses emitted as absolute bytes

### Analysis

The M80/L80 standard treats `ORG` in CSEG as still being relocatable. Source files should use `ASEG` if they want truly absolute addresses that won't be relocated.

For CP/M 2.2 (cpm22.asm) which is always loaded at a fixed address:
- Using ASEG would be cleaner - addresses are naturally absolute
- Current approach requires linker's `-p` to exactly match the ORG
- With ASEG, link at `-p 0` since addresses are already absolute

### Options

1. **Modify cpm22.asm to use ASEG** - Add `ASEG` directive before `ORG`, making addresses naturally absolute
2. **Keep current approach** - Program-relative with ORG adjustment, requires `-p e000` to match

### Files Affected
- `/home/wohl/um80_and_friends/um80/um80.py` - emit_word() subtracts ORG for PROGRAM_REL
- `/home/wohl/um80_and_friends/um80/ul80.py` - linker relocation handling
- `cpm22asm/cpm22.asm` - CP/M source (could add ASEG)

---

## 2. CP/M Emulator: Stuck in Disk Routines

**Status:** Open
**Component:** altair_emu.cc

### Problem

CP/M boots but gets stuck in BDOS disk routines (TRKSEC at 0xEBC3-0xEC0F) before printing any console output.

### Symptoms
- BIOS BOOT executes successfully
- Disk tables (DPH, DPB) are initialized
- SELDSK, SETTRK, SETSEC, READ calls happen
- No CONOUT calls occur (no prompt printed)
- PC oscillates around 0xEBFA-0xEC0C (TRKSEC routines)

### Possible Causes
1. **DPB parameters incorrect** - Block size, directory entries, allocation may not match disk geometry
2. **Disk read returning wrong data** - Empty disk image returns 0xE5 (correct for empty dir)
3. **BDOS internal state corruption** - Something in page zero or scratch areas wrong
4. **Console never reached** - CCP stuck trying to read $$$.SUB file

### Current Disk Configuration
```
DPB (at 0xF500):
  SPT = 26 sectors/track
  BSH = 3 (1024-byte blocks)
  BLM = 7
  EXM = 0
  DSM = 242 (max block number)
  DRM = 63 (64 directory entries)
  AL0/AL1 = 0xC0, 0x00
  CKS = 16
  OFF = 2 (reserved tracks)
```

### Next Steps
- Add tracing to see exactly which BIOS calls happen
- Verify DPB matches standard 8" SSSD geometry
- Check if BDOS is returning errors from disk operations
- Consider simplifying by returning "no disk" to skip $$$.SUB check

---

## 3. Console Output Verification Needed

**Status:** Open
**Component:** altair_emu.cc

### Problem

CONOUT BIOS function appears to never be called during boot, suggesting CCP/BDOS never reaches the point of printing the "A>" prompt.

### Related
This is likely a symptom of Issue #2 (stuck in disk routines).

---

## 4. ulib80 Library Output Is Not Reproducible

**Status:** Open
**Component:** ulib80

### Problem

`ulib80 -c lib.lib <same .rel files>` produces a different byte stream on every
run. Three runs over one unchanged set of `.rel` files gave three different
checksums of the same length; setting `PYTHONHASHSEED` to a fixed value makes
the output reproducible, so the ordering comes from iterating a `set` or `dict`
somewhere in the library writer.

### Impact

The archive is functionally correct (the linker resolves the same symbols), but
builds cannot be checked for reproducibility, and a byte comparison cannot be
used to tell whether a toolchain change altered a library. Found while checking
the blast radius of the 0.3.44 no-operand change against the uc80 libraries:
every one of the 97 `.rel` modules was byte-identical, yet `libc.lib` and
`runtime.lib` differed on every rebuild.

### Fix direction

Sort every symbol/module iteration in the writer, or iterate the input list
order that the caller supplied.

---

## Build Notes

### Rebuilding CP/M
```bash
cd cpm22asm
um80 -g cpm22.asm
ul80 -o cpm22.sys -S cpm22.sym -p e000 cpm22.rel
cp cpm22.sys ..
```

### Running Emulator
```bash
cd src && make altair_emu
cd ..
./src/altair_emu --cpm --disk-a=./drivea ./cpm22.sys
```

### Debug Mode
```bash
./src/altair_emu --cpm --debug --disk-a=./drivea ./cpm22.sys
```
