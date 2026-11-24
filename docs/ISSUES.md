# Open Issues

## 1. REL Format: Absolute ORG Representation

**Status:** Resolved (0.3.42).

**Component:** um80 assembler / ul80 linker

Since version 0.3.42, ul80 places ASEG (absolute) segments at their absolute
address and never relocates them. The change was verified against L80 3.44.
A module can mix a relocatable CSEG with an absolute ASEG block, for example an
interrupt or RST vector. Each segment is placed correctly.

The approach with a relocatable CSEG, `ORG` and `-p` still works as before for
code such as `cpm22.asm`.

### Problem

When um80 assembles code with `ORG <absolute_address>` in CSEG (the default
code segment), there is ambiguity about how the REL file should
represent an address.

**Current behavior:**

- `ORG 0xE000` in CSEG sets the location counter to an absolute address.
- um80 writes labels (for example COMMAND at 0xE35C) as PROGRAM_REL.
- um80 now subtracts the ORG (0xE000) to get the offset (0x035C).
- ul80 adds the code_base (the option -p) to relocate.

**Alternative approach - ASEG:**

- Code in ASEG uses `ADDR_ABSOLUTE` (type 0) for all addresses.
- ul80 does not relocate absolute addresses.
- SET_LOC would be `(0, 0xE000)`, and um80 would write the addresses as
  absolute bytes.

### Analysis

The standard of M80 and L80 treats `ORG` in CSEG as still relocatable. A
source file should use `ASEG` when the source file needs truly absolute
addresses that the linker does not relocate.

CP/M 2.2 (`cpm22.asm`) is always loaded at a fixed address. For this source
file:

- ASEG would be cleaner, because the addresses are naturally absolute.
- The current approach requires the option `-p` of ul80 to match the ORG
  exactly.
- With ASEG, run ul80 with `-p 0`. The addresses are already absolute.

### Options

1. **Modify cpm22.asm to use ASEG.** Add the `ASEG` directive before `ORG`.
   The addresses are then naturally absolute.
2. **Keep the current approach.** The addresses are program-relative with an
   ORG adjustment. This approach requires `-p e000` to match.

### Files Affected
- `/home/wohl/um80_and_friends/um80/um80.py`: emit_word() subtracts ORG for
  PROGRAM_REL
- `/home/wohl/um80_and_friends/um80/ul80.py`: the relocation handling of the
  linker
- `cpm22asm/cpm22.asm`: the CP/M source (could add ASEG)

---

## 2. CP/M Emulator: Stuck in Disk Routines

**Status:** Open

**Component:** altair_emu.cc

### Problem

CP/M boots, but then gets stuck in the BDOS disk routines (TRKSEC at
0xEBC3-0xEC0F). CP/M gets stuck before it prints any console output.

### Symptoms
- BIOS BOOT executes successfully.
- The disk tables (DPH, DPB) are initialized.
- The calls SELDSK, SETTRK, SETSEC and READ happen.
- No CONOUT calls occur (no prompt is printed).
- PC oscillates around 0xEBFA-0xEC0C (the TRKSEC routines).

### Possible Causes
1. **DPB parameters incorrect.** Block size, directory entries or allocation
   may not match the disk geometry.
2. **Disk read returns wrong data.** An empty disk image returns 0xE5. This
   value is correct for an empty directory.
3. **BDOS internal state corruption.** Something in page zero or in the
   scratch areas is wrong.
4. **Console never reached.** The CCP is stuck when it tries to read the
   $$$.SUB file.

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
- Add tracing to see exactly which BIOS calls happen.
- Verify that the DPB matches the standard 8" SSSD geometry.
- Check whether BDOS returns errors from disk operations.
- Consider simplifying the method: return "no disk" to skip the $$$.SUB check.

---

## 3. Console Output Verification Needed

**Status:** Open

**Component:** altair_emu.cc

### Problem

The CONOUT BIOS function appears never to be called during boot. The missing
call suggests that the CCP and BDOS never reach the point where they print the
"A>" prompt.

### Related
Issue #3 is likely a symptom of Issue #2 (stuck in disk routines).

---

## 4. ulib80 Library Output Is Not Reproducible

**Status:** Open

**Component:** ulib80

### Problem

`ulib80 -c lib.lib <same .rel files>` writes a different byte stream each time
you start ulib80. The test used one unchanged set of REL files. Three times,
the command gave three different checksums of the same length.

When you set `PYTHONHASHSEED` to a fixed value, the output is reproducible.
Therefore the order of the output comes from an iteration over a `set` or `dict` somewhere in the
library writer.

### Impact

The library file is functionally correct (the linker resolves the same
symbols). But you cannot check a build for reproducibility. You cannot use a
byte comparison to show whether a change in the toolchain altered a library.

The problem was found while a check was made of the blast radius of the
0.3.44 no-operand change against the uc80 libraries. Every one of the 97 `.rel`
modules was byte-identical. But `libc.lib` and `runtime.lib` differed on every
rebuild.

### Fix direction

Sort every symbol iteration and every module iteration in the writer.
Alternatively, iterate in the input list order that the caller supplied.

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
