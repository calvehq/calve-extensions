# `.calveignore`

The software extension decides which paths a scan skips, without Git. Rules live in `.calveignore` files. A file applies to paths below its own directory. The extension also has built-in software and language defaults; `calve ignore check <path>` reports which rule decided.

| Syntax | Meaning |
|---|---|
| `pattern` | One pattern per line |
| `# text` | A comment |
| `!pattern` | Negates: a matching path is not ignored |
| `/pattern` | Anchored to the file's directory |
| `pattern/` | Directories only, and everything below them |
| `*`, `?` | Stay within one path segment |
| `**` | Crosses separators; `**/` also matches zero levels |
| `\x` | Escapes the next character |

Rules are evaluated in order and the last matching rule wins.

```text
# Build output, except the one report we keep.
target/
*.log
!target/report.log
/generated/**/*.tmp
```

Calve always excludes `.calve/` itself, and never follows symlinks.
