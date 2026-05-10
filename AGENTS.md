# AGENTS.md

## Scope

- This repository is **public** and only for **retired** Hack The Box machines.
- Any **active/non-retired** machine content must **not** be stored here.
- Active/non-retired content must go to the private staging repository: `htb-pending-retirement`.

## Editorial policy

- Do **not** include public references to:
  - AI
  - ChatGPT
  - OpenAI
  - prompts
  - chats
  - assisted reconstruction
  - or any wording that suggests AI-generated or AI-assisted documentation.
- Keep writeups written as normal human-authored technical documentation.

## Multilingual documentation policy

- Repository structure and navigation are primarily in English.
- Machine documentation may be maintained in Spanish, English, and Catalan.
- Markdown files under `sources/` are canonical editable sources.
- PDF files under `reports/` are generated final artifacts.
- Do not translate PDFs directly when Markdown sources exist.
- Do not publish active-machine material.
- Do not perform mass multilingual migrations without a validated pilot.
- Keep each machine folder self-contained with README, metadata, sources, reports, and assets when available.

## Repository structure

Recommended structure for multilingual machine folders:

```text
machines/<difficulty>/<machine>/
├── README.md
├── metadata.yml
├── sources/
│   ├── es/
│   ├── en/
│   └── ca/
├── reports/
└── assets/
```

## Codex usage policy

Codex may assist with:

- folder structure;
- naming consistency;
- link checks;
- small PRs;
- mechanical repository updates;
- checking compliance with this file.

Codex must not make final decisions on:

- technical content;
- translated writeups;
- editorial meaning;
- repository architecture;
- mass migrations.

## Commit / merge message policy

- Any commit message, merge message, or pull request text must follow the editorial policy above.
- Use wording that is valid whether changes are merged via PR or committed directly to `main`.

## Index synchronization

When a machine is **added, renamed, removed, or made multilingual**, update the relevant indexes in the same change set:

1. Difficulty index: `machines/<difficulty>/README.md`
2. Root index: `README.md`

## Filenames

Preferred multilingual naming convention:

```text
<machine>.<lang>.md
<machine>.<lang>.pdf
<machine>.<lang>.cover.png
```

Supported language codes:

```text
es
en
ca
```
