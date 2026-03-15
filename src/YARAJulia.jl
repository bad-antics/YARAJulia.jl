"""
    YARAJulia

YARA-like pattern matching engine for Julia, designed for malware analysis
and threat detection. Supports hex patterns, text strings, regex, conditions,
and rule-based scanning.

# Quick Start
```julia
using YARAJulia

rule = yara_rule("detect_elf",
    strings = [
        yara_hex("elf_magic", "7f 45 4c 46"),
        yara_text("suspicious", "eval("),
    ],
    condition = :all_of_them
)

matches = scan(rule, read("suspicious_file", UInt8))
```
"""
module YARAJulia

export YaraRule, YaraString, YaraMatch, ScanResult,
       yara_rule, yara_hex, yara_text, yara_regex,
       scan, scan_file, compile_rules, match_count,
       RuleSet, add_rule!, scan_with_ruleset,
       parse_yara

# ─────────────────────────────────────────────────────────────────────────────
#                              TYPES
# ─────────────────────────────────────────────────────────────────────────────

"""Type of YARA string pattern."""
@enum StringType HEX_STRING TEXT_STRING REGEX_STRING

"""Modifiers for string matching."""
Base.@kwdef struct StringModifiers
    nocase::Bool = false       # Case-insensitive
    wide::Bool = false         # UTF-16LE encoding
    ascii_mod::Bool = true     # ASCII encoding (default)
    fullword::Bool = false     # Match whole words only
end

"""A YARA string pattern definition."""
struct YaraString
    id::String
    pattern::String
    string_type::StringType
    modifiers::StringModifiers
    compiled::Union{Vector{UInt8}, Regex, Nothing}
end

"""A single match occurrence."""
struct YaraMatch
    string_id::String
    offset::Int
    length::Int
    matched_data::Vector{UInt8}
end

"""Result of scanning data against a rule."""
struct ScanResult
    rule_name::String
    matched::Bool
    tags::Vector{String}
    matches::Vector{YaraMatch}
    metadata::Dict{String, Any}
end

"""Condition types for rule matching."""
@enum ConditionType begin
    ALL_OF_THEM      # All strings must match
    ANY_OF_THEM      # Any string must match
    N_OF_THEM        # At least N strings must match
    CUSTOM_CONDITION # Custom condition function
end

"""A YARA rule definition."""
struct YaraRule
    name::String
    tags::Vector{String}
    strings::Vector{YaraString}
    condition_type::ConditionType
    condition_n::Int  # For N_OF_THEM
    condition_fn::Union{Function, Nothing}  # For CUSTOM_CONDITION
    metadata::Dict{String, Any}
end

"""A collection of YARA rules."""
mutable struct RuleSet
    rules::Vector{YaraRule}
    name::String
end

RuleSet(name::String="default") = RuleSet(YaraRule[], name)

function Base.show(io::IO, rs::RuleSet)
    print(io, "RuleSet(\"$(rs.name)\", $(length(rs.rules)) rules)")
end

# ─────────────────────────────────────────────────────────────────────────────
#                              PATTERN CONSTRUCTORS
# ─────────────────────────────────────────────────────────────────────────────

"""
    yara_hex(id, hex_pattern; modifiers...) -> YaraString

Create a hex string pattern. Supports:
- Plain hex: `"4d 5a 90 00"`
- Wildcards: `"4d 5a ?? 00"` (single byte wildcard)
- Jumps: `"4d 5a [2-4] 00"` (2-4 byte jump)
- Alternatives: `"4d (5a | 5b) 90"`

# Example
```julia
yara_hex("mz_header", "4d 5a 90 00")
yara_hex("pe_sig", "50 45 00 00")
```
"""
function yara_hex(id::AbstractString, hex_pattern::AbstractString; kwargs...)
    mods = StringModifiers(; kwargs...)
    compiled = compile_hex_pattern(hex_pattern)
    YaraString(String(id), String(hex_pattern), HEX_STRING, mods, compiled)
end

"""
    yara_text(id, text; modifiers...) -> YaraString

Create a text string pattern.

# Example
```julia
yara_text("suspicious_str", "CreateRemoteThread")
yara_text("case_insens", "malware"; nocase=true)
```
"""
function yara_text(id::AbstractString, text::AbstractString; kwargs...)
    mods = StringModifiers(; kwargs...)
    compiled = _compile_text(String(text), mods)
    YaraString(String(id), String(text), TEXT_STRING, mods, compiled)
end

"""
    yara_regex(id, pattern; modifiers...) -> YaraString

Create a regex string pattern.

# Example
```julia
yara_regex("url_pattern", raw"https?://[\\w.-]+/[\\w./-]*")
```
"""
function yara_regex(id::AbstractString, pattern::AbstractString; kwargs...)
    mods = StringModifiers(; kwargs...)
    flags = mods.nocase ? "i" : ""
    compiled = Regex(String(pattern), flags)
    YaraString(String(id), String(pattern), REGEX_STRING, mods, compiled)
end

# ─────────────────────────────────────────────────────────────────────────────
#                              HEX PATTERN COMPILER
# ─────────────────────────────────────────────────────────────────────────────

"""Compiled hex pattern element."""
struct HexElement
    type::Symbol  # :byte, :wildcard, :jump, :alternative
    value::UInt8  # For :byte
    min_jump::Int  # For :jump
    max_jump::Int  # For :jump
    alternatives::Vector{UInt8}  # For :alternative
end

HexElement(type::Symbol, value::UInt8) = HexElement(type, value, 0, 0, UInt8[])
HexElement(type::Symbol, min_j::Int, max_j::Int) = HexElement(type, 0x00, min_j, max_j, UInt8[])
HexElement(type::Symbol, alts::Vector{UInt8}) = HexElement(type, 0x00, 0, 0, alts)

"""Compile a hex pattern string into a byte pattern for matching."""
function compile_hex_pattern(pattern::AbstractString)
    # Simple hex patterns: convert to byte array
    # For wildcards (??), we use a special marker approach
    bytes = UInt8[]
    tokens = split(strip(pattern))
    
    for token in tokens
        if token == "??"
            push!(bytes, 0x00)  # Placeholder, tracked separately
        elseif length(token) == 2 && all(c -> c in "0123456789abcdefABCDEF", token)
            push!(bytes, parse(UInt8, token; base=16))
        end
        # Skip jumps and alternatives in simple compilation
    end
    
    return bytes
end

"""Parse hex pattern into structured elements for advanced matching."""
function parse_hex_elements(pattern::AbstractString)::Vector{HexElement}
    elements = HexElement[]
    tokens = split(strip(pattern))
    i = 1
    
    while i <= length(tokens)
        token = tokens[i]
        
        if token == "??"
            push!(elements, HexElement(:wildcard, 0x00))
        elseif startswith(token, "[") && endswith(token, "]")
            # Jump: [N] or [N-M]
            inner = token[2:end-1]
            if occursin("-", inner)
                parts = split(inner, "-")
                push!(elements, HexElement(:jump, parse(Int, parts[1]), parse(Int, parts[2])))
            else
                n = parse(Int, inner)
                push!(elements, HexElement(:jump, n, n))
            end
        elseif startswith(token, "(")
            # Alternatives: (XX | YY | ZZ)
            alt_tokens = String[]
            # Collect until closing paren
            combined = token
            while !endswith(combined, ")") && i < length(tokens)
                i += 1
                combined *= " " * tokens[i]
            end
            inner = combined[2:end-1]  # Remove parens
            for alt in split(inner, "|")
                alt = strip(alt)
                if length(alt) == 2
                    push!(alt_tokens, alt)
                end
            end
            alts = UInt8[parse(UInt8, a; base=16) for a in alt_tokens]
            push!(elements, HexElement(:alternative, alts))
        elseif length(token) == 2 && all(c -> c in "0123456789abcdefABCDEF", token)
            push!(elements, HexElement(:byte, parse(UInt8, token; base=16)))
        end
        
        i += 1
    end
    
    return elements
end

"""Compile text pattern to bytes."""
function _compile_text(text::AbstractString, mods::StringModifiers)
    if mods.wide
        # UTF-16LE: interleave with 0x00
        result = UInt8[]
        for c in text
            push!(result, UInt8(c))
            push!(result, 0x00)
        end
        return result
    else
        return Vector{UInt8}(text)
    end
end

# ─────────────────────────────────────────────────────────────────────────────
#                              RULE CONSTRUCTOR
# ─────────────────────────────────────────────────────────────────────────────

"""
    yara_rule(name; strings, condition, tags, metadata) -> YaraRule

Create a YARA rule.

# Arguments
- `name`: Rule identifier
- `strings`: Vector of YaraString patterns
- `condition`: `:all_of_them`, `:any_of_them`, `(:n_of_them, N)`, or a function
- `tags`: Vector of string tags
- `metadata`: Dict of metadata key-value pairs

# Example
```julia
rule = yara_rule("detect_pe",
    strings = [yara_hex("mz", "4d 5a"), yara_hex("pe", "50 45 00 00")],
    condition = :all_of_them,
    tags = ["pe", "windows"],
    metadata = Dict("author" => "analyst", "severity" => 8)
)
```
"""
function yara_rule(name::AbstractString;
                   strings::Vector{YaraString} = YaraString[],
                   condition = :any_of_them,
                   tags::Vector{String} = String[],
                   metadata::Dict{String, Any} = Dict{String, Any}())
    
    n = String(name)
    if condition == :all_of_them
        return YaraRule(n, tags, strings, ALL_OF_THEM, 0, nothing, metadata)
    elseif condition == :any_of_them
        return YaraRule(n, tags, strings, ANY_OF_THEM, 0, nothing, metadata)
    elseif condition isa Tuple && condition[1] == :n_of_them
        return YaraRule(n, tags, strings, N_OF_THEM, condition[2], nothing, metadata)
    elseif condition isa Function
        return YaraRule(n, tags, strings, CUSTOM_CONDITION, 0, condition, metadata)
    else
        error("Unknown condition: $condition")
    end
end

# ─────────────────────────────────────────────────────────────────────────────
#                              MATCHING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

"""Find all occurrences of a byte pattern in data."""
function find_bytes(data::Vector{UInt8}, pattern::Vector{UInt8};
                    nocase::Bool=false)::Vector{Int}
    positions = Int[]
    isempty(pattern) && return positions
    plen = length(pattern)
    
    for i in 1:(length(data) - plen + 1)
        found = true
        for j in 1:plen
            a = data[i + j - 1]
            b = pattern[j]
            if nocase
                a = _tolower(a)
                b = _tolower(b)
            end
            if a != b
                found = false
                break
            end
        end
        if found
            push!(positions, i)
        end
    end
    
    return positions
end

"""Find matches using parsed hex elements (supports wildcards, jumps, alternatives)."""
function find_hex_elements(data::Vector{UInt8}, elements::Vector{HexElement})::Vector{Tuple{Int, Int}}
    matches = Tuple{Int, Int}[]
    isempty(elements) && return matches
    
    for start_pos in 1:length(data)
        match_len = _try_match_elements(data, start_pos, elements, 1)
        if match_len > 0
            push!(matches, (start_pos, match_len))
        end
    end
    
    return matches
end

"""Try to match elements starting at a position. Returns match length or 0."""
function _try_match_elements(data::Vector{UInt8}, pos::Int,
                              elements::Vector{HexElement}, elem_idx::Int)::Int
    pos > length(data) && elem_idx > length(elements) && return 0
    elem_idx > length(elements) && return 0
    
    consumed = 0
    idx = elem_idx
    current_pos = pos
    
    while idx <= length(elements)
        current_pos > length(data) && return 0
        elem = elements[idx]
        
        if elem.type == :byte
            current_pos > length(data) && return 0
            data[current_pos] != elem.value && return 0
            current_pos += 1
            consumed += 1
            
        elseif elem.type == :wildcard
            current_pos > length(data) && return 0
            current_pos += 1
            consumed += 1
            
        elseif elem.type == :alternative
            current_pos > length(data) && return 0
            data[current_pos] in elem.alternatives || return 0
            current_pos += 1
            consumed += 1
            
        elseif elem.type == :jump
            # Try each possible jump length
            for jump_len in elem.min_jump:elem.max_jump
                new_pos = current_pos + jump_len
                if new_pos <= length(data) + 1
                    rest_len = _try_match_elements(data, new_pos, elements, idx + 1)
                    if rest_len > 0 || idx == length(elements)
                        return consumed + jump_len + rest_len
                    end
                end
            end
            return 0
        end
        
        idx += 1
    end
    
    return consumed
end

"""Find regex matches in data."""
function find_regex(data::Vector{UInt8}, rx::Regex)::Vector{Tuple{Int, Int}}
    matches = Tuple{Int, Int}[]
    text = String(copy(data))
    
    for m in eachmatch(rx, text)
        offset = m.offset
        len = length(m.match)
        push!(matches, (offset, len))
    end
    
    return matches
end

"""Check if a match is a fullword (surrounded by non-alphanumeric chars)."""
function is_fullword(data::Vector{UInt8}, pos::Int, len::Int)::Bool
    # Check character before match
    if pos > 1
        c = data[pos - 1]
        _is_alnum(c) && return false
    end
    # Check character after match
    endpos = pos + len
    if endpos <= length(data)
        c = data[endpos]
        _is_alnum(c) && return false
    end
    return true
end

@inline function _tolower(c::UInt8)::UInt8
    (UInt8('A') <= c <= UInt8('Z')) ? c + 0x20 : c
end

@inline function _is_alnum(c::UInt8)::Bool
    (UInt8('a') <= c <= UInt8('z')) ||
    (UInt8('A') <= c <= UInt8('Z')) ||
    (UInt8('0') <= c <= UInt8('9')) ||
    c == UInt8('_')
end

# ─────────────────────────────────────────────────────────────────────────────
#                              SCANNING
# ─────────────────────────────────────────────────────────────────────────────

"""
    scan(rule::YaraRule, data::Vector{UInt8}) -> ScanResult

Scan data against a single YARA rule.

# Example
```julia
rule = yara_rule("test", strings=[yara_hex("sig", "4d 5a")])
result = scan(rule, read("file.exe"))
if result.matched
    for m in result.matches
        println("Found \$(m.string_id) at offset \$(m.offset)")
    end
end
```
"""
function scan(rule::YaraRule, data::Vector{UInt8})::ScanResult
    all_matches = YaraMatch[]
    matched_strings = Set{String}()
    
    for ys in rule.strings
        positions = _scan_string(ys, data)
        
        for (pos, len) in positions
            # Apply fullword modifier
            if ys.modifiers.fullword && !is_fullword(data, pos, len)
                continue
            end
            
            matched_data = data[pos:min(pos + len - 1, length(data))]
            push!(all_matches, YaraMatch(ys.id, pos, len, matched_data))
            push!(matched_strings, ys.id)
        end
    end
    
    # Evaluate condition
    rule_matched = _evaluate_condition(rule, matched_strings, all_matches, data)
    
    return ScanResult(rule.name, rule_matched, rule.tags, all_matches, rule.metadata)
end

"""Scan a single YaraString against data."""
function _scan_string(ys::YaraString, data::Vector{UInt8})::Vector{Tuple{Int, Int}}
    if ys.string_type == HEX_STRING
        # Use advanced matching if pattern has wildcards/jumps
        if occursin("??", ys.pattern) || occursin("[", ys.pattern) || occursin("(", ys.pattern)
            elements = parse_hex_elements(ys.pattern)
            return find_hex_elements(data, elements)
        else
            positions = find_bytes(data, ys.compiled isa Vector{UInt8} ? ys.compiled : UInt8[];
                                   nocase=ys.modifiers.nocase)
            plen = ys.compiled isa Vector{UInt8} ? length(ys.compiled) : 0
            return [(p, plen) for p in positions]
        end
        
    elseif ys.string_type == TEXT_STRING
        positions = find_bytes(data, ys.compiled isa Vector{UInt8} ? ys.compiled : UInt8[];
                               nocase=ys.modifiers.nocase)
        plen = ys.compiled isa Vector{UInt8} ? length(ys.compiled) : 0
        return [(p, plen) for p in positions]
        
    elseif ys.string_type == REGEX_STRING
        return find_regex(data, ys.compiled isa Regex ? ys.compiled : Regex(ys.pattern))
    end
    
    return Tuple{Int, Int}[]
end

"""Evaluate the rule condition."""
function _evaluate_condition(rule::YaraRule, matched_strings::Set{String},
                              matches::Vector{YaraMatch}, data::Vector{UInt8})::Bool
    total_strings = length(rule.strings)
    num_matched = length(matched_strings)
    
    if rule.condition_type == ALL_OF_THEM
        return num_matched == total_strings && total_strings > 0
    elseif rule.condition_type == ANY_OF_THEM
        return num_matched > 0
    elseif rule.condition_type == N_OF_THEM
        return num_matched >= rule.condition_n
    elseif rule.condition_type == CUSTOM_CONDITION
        return rule.condition_fn !== nothing && rule.condition_fn(matched_strings, matches, data)
    end
    
    return false
end

"""
    scan_file(rule::YaraRule, filepath::String) -> ScanResult

Scan a file against a YARA rule.
"""
function scan_file(rule::YaraRule, filepath::AbstractString)::ScanResult
    data = read(filepath)
    return scan(rule, data)
end

"""
    match_count(result::ScanResult) -> Int

Get the total number of match occurrences.
"""
match_count(result::ScanResult) = length(result.matches)

"""
    match_count(result::ScanResult, string_id::String) -> Int

Get the number of matches for a specific string identifier.
"""
function match_count(result::ScanResult, string_id::String)
    count(m -> m.string_id == string_id, result.matches)
end

# ─────────────────────────────────────────────────────────────────────────────
#                              RULESET
# ─────────────────────────────────────────────────────────────────────────────

"""Add a rule to a ruleset."""
function add_rule!(rs::RuleSet, rule::YaraRule)
    push!(rs.rules, rule)
    return rs
end

"""
    scan_with_ruleset(rs::RuleSet, data::Vector{UInt8}) -> Vector{ScanResult}

Scan data against all rules in a ruleset.
Returns only matching results.
"""
function scan_with_ruleset(rs::RuleSet, data::Vector{UInt8})::Vector{ScanResult}
    results = ScanResult[]
    for rule in rs.rules
        result = scan(rule, data)
        if result.matched
            push!(results, result)
        end
    end
    return results
end

"""
    compile_rules(rules::Vector{YaraRule}) -> RuleSet

Compile multiple rules into a RuleSet for efficient scanning.
"""
function compile_rules(rules::Vector{YaraRule}; name::String="compiled")
    rs = RuleSet(name)
    for rule in rules
        add_rule!(rs, rule)
    end
    return rs
end

# ─────────────────────────────────────────────────────────────────────────────
#                              RULE PARSER (YARA syntax)
# ─────────────────────────────────────────────────────────────────────────────

"""
    parse_yara(source::String) -> Vector{YaraRule}

Parse YARA rules from a YARA-format string.

# Supported syntax
```
rule rulename : tag1 tag2 {
    meta:
        author = "analyst"
        severity = 8
    strings:
        \$hex1 = { 4D 5A 90 00 }
        \$text1 = "suspicious string"
    condition:
        all of them
}
```
"""
function parse_yara(source::String)::Vector{YaraRule}
    rules = YaraRule[]
    
    # Simple parser for YARA rule syntax
    rule_regex = r"rule\s+(\w+)(?:\s*:\s*([\w\s]+))?\s*\{(.*?)\n\s*\}"s
    
    for m in eachmatch(rule_regex, source)
        name = m.captures[1]
        tags = m.captures[2] !== nothing ? split(strip(m.captures[2])) : String[]
        body = m.captures[3]
        
        meta = Dict{String, Any}()
        strings = YaraString[]
        condition = :any_of_them
        
        # Parse sections
        sections = _split_sections(body)
        
        if haskey(sections, "meta")
            meta = _parse_meta(sections["meta"])
        end
        
        if haskey(sections, "strings")
            strings = _parse_strings(sections["strings"])
        end
        
        if haskey(sections, "condition")
            condition = _parse_condition(sections["condition"])
        end
        
        push!(rules, yara_rule(String(name); strings=strings, condition=condition,
                                tags=collect(String, tags), metadata=meta))
    end
    
    return rules
end

"""Split rule body into sections (meta, strings, condition)."""
function _split_sections(body::AbstractString)::Dict{String, String}
    sections = Dict{String, String}()
    current_section = ""
    current_content = String[]
    
    for line in split(strip(body), "\n")
        line = strip(line)
        if line in ["meta:", "strings:", "condition:"]
            if !isempty(current_section)
                sections[current_section] = join(current_content, "\n")
            end
            current_section = line[1:end-1]
            current_content = String[]
        elseif !isempty(current_section)
            push!(current_content, line)
        end
    end
    
    if !isempty(current_section)
        sections[current_section] = join(current_content, "\n")
    end
    
    return sections
end

"""Parse metadata section."""
function _parse_meta(text::AbstractString)::Dict{String, Any}
    meta = Dict{String, Any}()
    for line in split(strip(text), "\n")
        line = strip(line)
        isempty(line) && continue
        m = match(r"(\w+)\s*=\s*(.*)", line)
        m === nothing && continue
        key = m.captures[1]
        val = strip(m.captures[2])
        # Try to parse as number or keep as string
        if startswith(val, "\"") && endswith(val, "\"")
            meta[key] = val[2:end-1]
        else
            try
                meta[key] = parse(Int, val)
            catch
                meta[key] = val
            end
        end
    end
    return meta
end

"""Parse strings section."""
function _parse_strings(text::AbstractString)::Vector{YaraString}
    strings = YaraString[]
    for line in split(strip(text), "\n")
        line = strip(line)
        isempty(line) && continue
        
        # Hex string: $id = { hex bytes }
        m = match(r"\$(\w+)\s*=\s*\{\s*(.*?)\s*\}", line)
        if m !== nothing
            push!(strings, yara_hex(m.captures[1], m.captures[2]))
            continue
        end
        
        # Text string: $id = "text"
        m = match(r"\$(\w+)\s*=\s*\"(.*?)\"(?:\s+(nocase|wide|fullword|ascii))*", line)
        if m !== nothing
            kwargs = Dict{Symbol, Bool}()
            if m.captures[3] !== nothing
                mod = m.captures[3]
                if mod == "nocase"
                    kwargs[:nocase] = true
                elseif mod == "wide"
                    kwargs[:wide] = true
                elseif mod == "fullword"
                    kwargs[:fullword] = true
                end
            end
            push!(strings, yara_text(m.captures[1], m.captures[2]; kwargs...))
            continue
        end
        
        # Regex: $id = /pattern/
        m = match(r"\$(\w+)\s*=\s*/(.*?)/([i]*)", line)
        if m !== nothing
            kwargs = Dict{Symbol, Bool}()
            if occursin("i", m.captures[3])
                kwargs[:nocase] = true
            end
            push!(strings, yara_regex(m.captures[1], m.captures[2]; kwargs...))
            continue
        end
    end
    return strings
end

"""Parse condition section."""
function _parse_condition(text::AbstractString)
    text = strip(text)
    
    if text == "all of them"
        return :all_of_them
    elseif text == "any of them"
        return :any_of_them
    elseif startswith(text, "any of them") || text == "true"
        return :any_of_them
    else
        m = match(r"(\d+)\s+of\s+them", text)
        if m !== nothing
            return (:n_of_them, parse(Int, m.captures[1]))
        end
    end
    
    return :any_of_them
end

end # module YARAJulia
