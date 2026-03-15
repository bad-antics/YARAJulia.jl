# YARAJulia.jl

[![Tests](https://img.shields.io/badge/tests-99%20passed-brightgreen)]()

A pure-Julia YARA-like pattern matching engine for malware analysis, threat detection, and binary scanning. No external dependencies required.

## Features

- **Hex patterns** — plain bytes, wildcards (`??`), jumps (`[N-M]`), alternatives (`(XX|YY)`)
- **Text patterns** — plain, case-insensitive (`nocase`), UTF-16LE (`wide`), word-boundary (`fullword`)
- **Regex patterns** — full regex support with optional case-insensitive flag
- **Rule conditions** — `all of them`, `any of them`, `N of them`, custom functions
- **RuleSet** — group and scan with multiple rules at once
- **YARA syntax parser** — parse standard YARA rule files
- **Zero dependencies** — pure Julia implementation

## Installation

```julia
using Pkg
Pkg.add("YARAJulia")
```

## Quick Start

```julia
using YARAJulia

# Detect PE executables
rule = yara_rule("detect_pe",
    strings = [
        yara_hex("mz_header", "4d 5a 90 00"),
        yara_hex("pe_sig", "50 45 00 00"),
    ],
    condition = :all_of_them,
    tags = ["pe", "windows"]
)

result = scan(rule, read("suspicious.exe"))
if result.matched
    println("PE file detected! $(match_count(result)) matches")
    for m in result.matches
        println("  $(m.string_id) at offset $(m.offset)")
    end
end
```

## Pattern Types

### Hex Patterns

```julia
# Plain hex bytes
yara_hex("magic", "7f 45 4c 46")          # ELF magic

# Wildcards (any byte)
yara_hex("sig", "4d 5a ?? 00")

# Jumps (variable-length gaps)
yara_hex("spaced", "4d 5a [2-8] 50 45")

# Alternatives
yara_hex("variant", "4d (5a | 5b) 90 00")
```

### Text Patterns

```julia
yara_text("cmd", "CreateRemoteThread")
yara_text("cmd_ci", "createremotethread"; nocase=true)
yara_text("wide_str", "kernel32"; wide=true)
yara_text("word", "malware"; fullword=true)
```

### Regex Patterns

```julia
yara_regex("url", raw"https?://[\w.-]+/[\w./-]+")
yara_regex("email", raw"[\w.]+@[\w.]+\.\w+"; nocase=true)
```

## Rule Conditions

```julia
# All patterns must match
yara_rule("strict", strings=patterns, condition=:all_of_them)

# Any pattern must match
yara_rule("loose", strings=patterns, condition=:any_of_them)

# At least N patterns must match
yara_rule("threshold", strings=patterns, condition=(:n_of_them, 3))

# Custom condition function
yara_rule("custom", strings=patterns,
    condition=(matched, matches, data) -> length(matches) >= 5)
```

## RuleSets

```julia
rs = RuleSet("malware_detection")
add_rule!(rs, rule1)
add_rule!(rs, rule2)

# Scan against all rules, returns only matching results
results = scan_with_ruleset(rs, data)

# Or compile from a vector
rs = compile_rules([rule1, rule2]; name="compiled")
```

## YARA Syntax Parser

```julia
source = raw"""
rule detect_elf : linux {
    meta:
        author = "analyst"
        severity = 8
    strings:
        $magic = { 7F 45 4C 46 }
        $suspicious = "eval("
    condition:
        all of them
}
"""

rules = parse_yara(source)
result = scan(rules[1], file_data)
```

## File Scanning

```julia
result = scan_file(rule, "/path/to/file")
```

## API Reference

| Function | Description |
|----------|-------------|
| `yara_hex(id, pattern)` | Create hex byte pattern |
| `yara_text(id, text; nocase, wide, fullword)` | Create text pattern |
| `yara_regex(id, pattern; nocase)` | Create regex pattern |
| `yara_rule(name; strings, condition, tags, metadata)` | Create a rule |
| `scan(rule, data)` | Scan data against a rule |
| `scan_file(rule, path)` | Scan a file against a rule |
| `match_count(result)` | Total match count |
| `match_count(result, id)` | Match count for a string ID |
| `compile_rules(rules)` | Compile rules into a RuleSet |
| `scan_with_ruleset(rs, data)` | Scan with multiple rules |
| `parse_yara(source)` | Parse YARA syntax into rules |

## License

MIT
