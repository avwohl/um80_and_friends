# Writing the documentation

The documents of um80_and_friends are written in the style of ASD-STE100
Simplified Technical English (STE). STE is a controlled language for technical
text. It uses short sentences, one name for each item and a small set of words.
Many readers of these documents do not have English as their first language.
STE makes the text easier for them to read and to translate by machine.

This file tells you how to write a new document or change an old one.
[glossary.md](glossary.md) gives the names to use.

## Files that follow these rules

- README.md and CHANGELOG.md
- every Markdown file in docs/
- the man pages in docs/man/
- the `--help` text of each tool: the strings in `help=`, `description=` and
  `epilog=`
- tools/dbg2elf_proto/README.md

These files do not follow the rules:

- docs/project.txt and docs/build_rom.md. These two files are task notes. The
  project keeps them as a record.
- the comments and the docstrings in the Python code
- LICENSE

## Before you write

1. Read [glossary.md](glossary.md). Use the names in its "Term" column.
2. If you need a name that is not in the glossary, add the name to
   docs/glossary.md in the same change.
3. Decide the tier of each part of your text. The next section gives the tiers.

## Tiers

Each part of a document has one tier. The tier tells you which rules apply.

| Tier | Text | Sentence limit |
|---|---|---|
| A, procedure | Steps that the reader does: install, build, test, troubleshooting, examples, warnings | 20 words |
| B, description | How a tool works, what a feature does, a man page DESCRIPTION, a CHANGELOG item | 25 words |
| C, reference | Tables of options, error codes and file types. The one-line `--help` text of an option | none |
| D, record | Measurements, history, rationale, known issues | none, but the paragraph rules apply |
| E, frozen | Code blocks, code spans, commands, program messages, URLs, quoted text | do not change |

A code span, a number with its unit, a file name and a hyphenated word each
count as one word.

Tier D text keeps every hedge, condition and comparison. Words such as "only",
"not yet", "about" and "as measured on" are facts. Do not delete them to make a
sentence shorter. If a sentence is long because the idea has a condition, split
the sentence into the condition and the statement.

## Rules

### Paragraphs and sentences

- Give each paragraph one topic. A paragraph has at most 6 sentences.
- When a text has many cases, use a vertical list or a table.
- When a text compares how M80, MAC, RMAC and um80 read the same source, use a
  table. Put the columns in this order: the source text, M80, MAC, RMAC, um80
  without `--dri`, um80 with `--dri`. Use only the columns that apply.
- In a procedure, give one instruction in each sentence. Use the imperative.
  Put the condition first: "If the test fails, run it again with `-v`."
- Put a WARNING or a CAUTION before the step that it is about. A WARNING is
  for data loss. A CAUTION is for wrong output or lost work.

### Words

- Give one item one name (STE rule 1.11). The glossary gives the name.
- Use the active voice. Write "um80 writes the REL file", not "the REL file is
  written".
- Do not use semicolons. Write two sentences.
- Do not use contractions. Write "does not", not "doesn't".
- Do not use "e.g.", "i.e.", "etc.", "vs." or "via". Write "for example", "that
  is", the names of the items, "compared with" or "through".
- Do not start a sentence with "This", "That", "It" or "They" alone for a thing
  that an earlier sentence names. Write the name again.
- Do not use phrasal verbs such as "set up", "carry out" or "go round". The
  glossary gives the replacement.
- Use American spelling: "behavior", "honor", "labeled".
- Do not use a word that ends in "-ing" in a sentence, except in a technical
  noun such as "operating system". A heading can have such a word.
- Do not use "simply", "just" or "easily".

### Headings

- Do not rename or remove a heading. Other documents, comments in the code and
  other projects link to its anchor.
- Give a new heading a text that no other heading in the file has.

### Code and quoted text

Do not change a code block, a code span, a command, a program message or a URL
to make the text agree with these rules. Do not change quoted text from a
manual.

## CHANGELOG entries

Write a new entry at the top of CHANGELOG.md, under the heading of the next
release. Use these headings in the release: Added, Changed, Fixed, Removed,
Known issues.

For each change:

1. Write one sentence that says what changed.
2. Write what was wrong before, with an example.
3. Write how the change was measured: the tool, the version, the date.
4. Name the tests that check the change.

Start each list item with the tool that changed, for example "um80 assembler:".
Indent the continuation lines of a list item by two spaces.

## Man pages and the --help text

- A man page is troff source. Do not break the markup. A text line must not
  start with "." or "'". Write `\&` before such a character.
- The DESCRIPTION section is tier B. The text for each option is tier C.
- For a long option description, use a list (`.RS`, `.IP \(bu 2`, `.RE`).
- The man page and the `--help` text must agree.
- In the `--help` text, write a "%" as "%%". argparse reads one "%" as a format
  character.

## Check your text

Run this test:

```bash
python3 -m pytest tests/test_docs_style.py
```

The test finds semicolons, contractions, Latin abbreviations, long paragraphs
and errors in the man pages. The test cannot find a wrong name or a wrong fact.
Read your text again before you commit.

The [STE skill](https://github.com/avwohl/claude-skills/blob/main/skills/simplified-technical-english.md)
gives all the rules, with software examples.
[ste_check.py](https://github.com/avwohl/claude-skills/blob/main/tools/ste_check.py)
does more checks than the test:

```bash
python3 ste_check.py --tier B docs/EXTENSIONS.md
```

ste_check.py reports some false positives for its checks 2.1 and 3.5. Read
each report. Do not change correct text only to make the report empty.

## The standard

ASD-STE100 is the standard of ASD, Brussels. You can get a free copy from
<https://asd-ste100.org/>. The documents of this project are written in the
style of STE. Do not write that they are "ASD-STE100 compliant": nobody checked
them against the STE dictionary. Do not copy the STE dictionary into this
project.
