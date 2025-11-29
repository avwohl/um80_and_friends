# Open Issues

## 1. REL Format: Absolute ORG Representation

**Status:** Open
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
