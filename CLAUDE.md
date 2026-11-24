# um80_and_friends

Python versions of the Microsoft MACRO-80 tools (um80, ul80, ulib80, ucref80)
plus ud80, ux80, udb80 and dbg2elf. README.md and docs/ are the reference.
This file holds only what a session must know that the code does not say.

## Documentation is in Simplified Technical English

All documentation is written in the style of ASD-STE100 Simplified Technical
English (STE): README.md, CHANGELOG.md, docs/*.md, the man pages in docs/man/,
and the `--help` text (`help=`, `description=`, `epilog=` strings). The
exceptions are docs/project.txt and docs/build_rom.md (task notes kept as a
record) and code comments and docstrings.

Before you write or change any of it:

1. Read docs/writing.md: the rules for this project (tiers, paragraph and
   sentence limits, comparison tables, CHANGELOG format, man pages).
2. Read docs/glossary.md: one name for each item, the registered technical
   verbs, words to avoid. A new term goes into the glossary in the same commit.
3. Read ~/src/claude-skills/skills/simplified-technical-english.md for the
   full rules.

After the change:

- `python3 -m pytest tests/test_docs_style.py` must pass (semicolons,
  contractions, Latin abbreviations, paragraphs over 6 sentences, sentences
  over 40 words, mandoc errors, `--help` that does not print).
- `python3 ~/src/claude-skills/tools/ste_check.py --tier B FILE` gives more
  checks. Its 2.1 and 3.5 reports are often false positives: read them.

Keep every fact and every hedge when you shorten text: a hedge such as "only",
"not yet" or "as measured" is a fact. Keep each behavior attached to the right
program (M80, MAC, RMAC, um80 without `--dri`, um80 with `--dri`, L80, ul80).
Do not rename a heading: other documents, code comments and other projects
link to its anchor. Put a documentation change in its own commit, apart from
code changes.
