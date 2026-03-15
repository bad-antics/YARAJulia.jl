using Test
using YARAJulia

@testset "YARAJulia.jl" begin

    @testset "yara_hex" begin
        s = yara_hex("test", "4d 5a 90 00")
        @test s.id == "test"
        @test s.string_type == YARAJulia.HEX_STRING
        @test s.compiled == UInt8[0x4d, 0x5a, 0x90, 0x00]
    end

    @testset "yara_text" begin
        s = yara_text("msg", "hello world")
        @test s.id == "msg"
        @test s.string_type == YARAJulia.TEXT_STRING
        @test s.compiled == Vector{UInt8}("hello world")
        
        # Wide string
        sw = yara_text("wide_msg", "AB"; wide=true)
        @test sw.compiled == UInt8[0x41, 0x00, 0x42, 0x00]
    end

    @testset "yara_regex" begin
        s = yara_regex("url", raw"https?://[\w.-]+")
        @test s.id == "url"
        @test s.string_type == YARAJulia.REGEX_STRING
        @test s.compiled isa Regex
        
        # Case insensitive
        s2 = yara_regex("ci", "test"; nocase=true)
        @test s2.compiled isa Regex
    end

    @testset "yara_rule" begin
        r = yara_rule("test_rule",
            strings = [yara_hex("sig", "4d 5a")],
            condition = :any_of_them,
            tags = ["malware"],
            metadata = Dict{String,Any}("author" => "test"))
        @test r.name == "test_rule"
        @test r.tags == ["malware"]
        @test length(r.strings) == 1
        @test r.condition_type == YARAJulia.ANY_OF_THEM
        @test r.metadata["author"] == "test"
    end

    @testset "yara_rule conditions" begin
        strings = [yara_hex("a", "41"), yara_hex("b", "42")]
        
        r1 = yara_rule("all", strings=strings, condition=:all_of_them)
        @test r1.condition_type == YARAJulia.ALL_OF_THEM
        
        r2 = yara_rule("any", strings=strings, condition=:any_of_them)
        @test r2.condition_type == YARAJulia.ANY_OF_THEM
        
        r3 = yara_rule("n_of", strings=strings, condition=(:n_of_them, 1))
        @test r3.condition_type == YARAJulia.N_OF_THEM
        @test r3.condition_n == 1
        
        r4 = yara_rule("custom", strings=strings,
                        condition=(matched, matches, data) -> length(matches) > 2)
        @test r4.condition_type == YARAJulia.CUSTOM_CONDITION
    end

    @testset "find_bytes - basic" begin
        data = UInt8[1, 2, 3, 4, 5, 1, 2, 3]
        pattern = UInt8[1, 2, 3]
        
        positions = YARAJulia.find_bytes(data, pattern)
        @test positions == [1, 6]
        
        # No match
        @test isempty(YARAJulia.find_bytes(data, UInt8[9, 9]))
        
        # Empty pattern
        @test isempty(YARAJulia.find_bytes(data, UInt8[]))
    end

    @testset "find_bytes - nocase" begin
        data = Vector{UInt8}("Hello World hello")
        pattern = Vector{UInt8}("hello")
        
        positions = YARAJulia.find_bytes(data, pattern; nocase=true)
        @test 1 in positions
        @test 13 in positions
    end

    @testset "find_regex" begin
        data = Vector{UInt8}("visit http://example.com and https://test.org")
        rx = r"https?://[\w.]+"
        
        matches = YARAJulia.find_regex(data, rx)
        @test length(matches) == 2
        @test matches[1][1] == 7  # "http://example.com" starts at 7
    end

    @testset "is_fullword" begin
        data = Vector{UInt8}("the malware is bad")
        @test YARAJulia.is_fullword(data, 5, 7)   # "malware" at pos 5
        @test YARAJulia.is_fullword(data, 1, 3)    # "the" at start
        @test YARAJulia.is_fullword(data, 16, 3)   # "bad" at end
        @test !YARAJulia.is_fullword(data, 5, 3)   # "mal" is part of word
    end

    @testset "scan - hex pattern" begin
        data = UInt8[0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]
        rule = yara_rule("pe_detect",
            strings = [yara_hex("mz", "4d 5a 90 00")],
            condition = :any_of_them)
        
        result = scan(rule, data)
        @test result.matched
        @test result.rule_name == "pe_detect"
        @test length(result.matches) == 1
        @test result.matches[1].offset == 1
        @test result.matches[1].matched_data == UInt8[0x4d, 0x5a, 0x90, 0x00]
    end

    @testset "scan - text pattern" begin
        data = Vector{UInt8}("This file contains malicious code eval(payload)")
        rule = yara_rule("detect_eval",
            strings = [yara_text("eval_call", "eval(")],
            condition = :any_of_them)
        
        result = scan(rule, data)
        @test result.matched
        @test match_count(result) == 1
        @test match_count(result, "eval_call") == 1
    end

    @testset "scan - regex pattern" begin
        data = Vector{UInt8}("Connect to http://evil.com/payload.exe for download")
        rule = yara_rule("url_detect",
            strings = [yara_regex("url", raw"https?://[\w.-]+/[\w.-]+")],
            condition = :any_of_them)
        
        result = scan(rule, data)
        @test result.matched
        @test length(result.matches) >= 1
    end

    @testset "scan - all_of_them" begin
        data = UInt8[0x4d, 0x5a, 0x50, 0x45, 0x00, 0x00]
        rule = yara_rule("pe_full",
            strings = [
                yara_hex("mz", "4d 5a"),
                yara_hex("pe", "50 45"),
            ],
            condition = :all_of_them)
        
        result = scan(rule, data)
        @test result.matched
        
        # Missing one pattern
        data2 = UInt8[0x4d, 0x5a, 0x00, 0x00, 0x00, 0x00]
        result2 = scan(rule, data2)
        @test !result2.matched
    end

    @testset "scan - n_of_them" begin
        data = Vector{UInt8}("password hash credential")
        rule = yara_rule("suspicious",
            strings = [
                yara_text("s1", "password"),
                yara_text("s2", "hash"),
                yara_text("s3", "credential"),
                yara_text("s4", "exploit"),
            ],
            condition = (:n_of_them, 2))
        
        result = scan(rule, data)
        @test result.matched  # 3 of 4 match, need 2
    end

    @testset "scan - nocase" begin
        data = Vector{UInt8}("MALWARE Detection malware")
        rule = yara_rule("nocase_test",
            strings = [yara_text("mal", "malware"; nocase=true)],
            condition = :any_of_them)
        
        result = scan(rule, data)
        @test result.matched
        @test match_count(result) == 2
    end

    @testset "scan - fullword" begin
        data = Vector{UInt8}("the malware is malwarebytes")
        rule = yara_rule("fullword_test",
            strings = [yara_text("mal", "malware"; fullword=true)],
            condition = :any_of_them)
        
        result = scan(rule, data)
        @test result.matched
        @test match_count(result) == 1  # Only standalone "malware", not "malwarebytes"
    end

    @testset "scan - no match" begin
        data = UInt8[0x00, 0x00, 0x00]
        rule = yara_rule("no_match",
            strings = [yara_hex("sig", "ff ff ff")],
            condition = :any_of_them)
        
        result = scan(rule, data)
        @test !result.matched
        @test isempty(result.matches)
    end

    @testset "scan - custom condition" begin
        data = Vector{UInt8}("test test test test test")
        rule = yara_rule("custom_cond",
            strings = [yara_text("t", "test")],
            condition = (matched, matches, d) -> length(matches) >= 3)
        
        result = scan(rule, data)
        @test result.matched  # "test" appears 5 times
    end

    @testset "scan - hex wildcards" begin
        data = UInt8[0x4d, 0x5a, 0xaa, 0x00]
        rule = yara_rule("wildcard_test",
            strings = [yara_hex("sig", "4d 5a ?? 00")],
            condition = :any_of_them)
        
        result = scan(rule, data)
        @test result.matched
    end

    @testset "scan_file" begin
        # Create a temp file
        tmpfile = tempname()
        write(tmpfile, UInt8[0x4d, 0x5a, 0x90, 0x00])
        
        rule = yara_rule("file_test",
            strings = [yara_hex("mz", "4d 5a")],
            condition = :any_of_them)
        
        result = scan_file(rule, tmpfile)
        @test result.matched
        rm(tmpfile)
    end

    @testset "match_count" begin
        data = Vector{UInt8}("aaa bbb aaa ccc aaa")
        rule = yara_rule("count_test",
            strings = [
                yara_text("a", "aaa"),
                yara_text("b", "bbb"),
            ],
            condition = :any_of_them)
        
        result = scan(rule, data)
        @test match_count(result) == 4  # 3 "aaa" + 1 "bbb"
        @test match_count(result, "a") == 3
        @test match_count(result, "b") == 1
    end

    @testset "RuleSet" begin
        rs = RuleSet("test_set")
        @test length(rs.rules) == 0
        
        r1 = yara_rule("rule1", strings=[yara_hex("a", "41")])
        r2 = yara_rule("rule2", strings=[yara_hex("b", "42")])
        
        add_rule!(rs, r1)
        add_rule!(rs, r2)
        @test length(rs.rules) == 2
        
        io = IOBuffer()
        show(io, rs)
        @test occursin("test_set", String(take!(io)))
    end

    @testset "scan_with_ruleset" begin
        rs = RuleSet("malware_rules")
        add_rule!(rs, yara_rule("has_A",
            strings=[yara_text("a", "A")], condition=:any_of_them))
        add_rule!(rs, yara_rule("has_Z",
            strings=[yara_text("z", "Z")], condition=:any_of_them))
        add_rule!(rs, yara_rule("has_X",
            strings=[yara_text("x", "X")], condition=:any_of_them))
        
        data = Vector{UInt8}("Hello A World")
        results = scan_with_ruleset(rs, data)
        @test length(results) == 1
        @test results[1].rule_name == "has_A"
    end

    @testset "compile_rules" begin
        rules = [
            yara_rule("r1", strings=[yara_hex("a", "41")]),
            yara_rule("r2", strings=[yara_hex("b", "42")]),
        ]
        rs = compile_rules(rules; name="compiled_set")
        @test length(rs.rules) == 2
        @test rs.name == "compiled_set"
    end

    @testset "parse_yara - basic" begin
        source = """
        rule test_rule : tag1 tag2 {
            meta:
                author = "analyst"
                severity = 5
            strings:
                \$hex1 = { 4D 5A 90 00 }
                \$text1 = "suspicious"
            condition:
                any of them
        }
        """
        
        rules = parse_yara(source)
        @test length(rules) == 1
        @test rules[1].name == "test_rule"
        @test "tag1" in rules[1].tags
        @test "tag2" in rules[1].tags
        @test rules[1].metadata["author"] == "analyst"
        @test rules[1].metadata["severity"] == 5
        @test length(rules[1].strings) == 2
    end

    @testset "parse_yara - multiple rules" begin
        source = """
        rule rule1 {
            strings:
                \$a = { 41 42 }
            condition:
                all of them
        }
        
        rule rule2 {
            strings:
                \$b = "test"
            condition:
                any of them
        }
        """
        
        rules = parse_yara(source)
        @test length(rules) == 2
        @test rules[1].name == "rule1"
        @test rules[2].name == "rule2"
    end

    @testset "parse_yara - n_of_them" begin
        source = """
        rule n_rule {
            strings:
                \$a = "test1"
                \$b = "test2"
                \$c = "test3"
            condition:
                2 of them
        }
        """
        
        rules = parse_yara(source)
        @test rules[1].condition_type == YARAJulia.N_OF_THEM
        @test rules[1].condition_n == 2
    end

    @testset "parse_hex_elements" begin
        # Simple hex
        elems = YARAJulia.parse_hex_elements("4d 5a 90")
        @test length(elems) == 3
        @test elems[1].type == :byte
        @test elems[1].value == 0x4d
        
        # Wildcard
        elems2 = YARAJulia.parse_hex_elements("4d ?? 90")
        @test elems2[2].type == :wildcard
        
        # Jump
        elems3 = YARAJulia.parse_hex_elements("4d [2-4] 90")
        @test elems3[2].type == :jump
        @test elems3[2].min_jump == 2
        @test elems3[2].max_jump == 4
        
        # Alternative
        elems4 = YARAJulia.parse_hex_elements("4d (5a | 5b) 90")
        @test elems4[2].type == :alternative
        @test 0x5a in elems4[2].alternatives
        @test 0x5b in elems4[2].alternatives
    end

    @testset "ScanResult fields" begin
        r = ScanResult("test", true, ["tag1"], YaraMatch[], Dict{String,Any}())
        @test r.rule_name == "test"
        @test r.matched
        @test r.tags == ["tag1"]
    end

    @testset "YaraMatch fields" begin
        m = YaraMatch("sig", 42, 4, UInt8[0x4d, 0x5a, 0x90, 0x00])
        @test m.string_id == "sig"
        @test m.offset == 42
        @test m.length == 4
        @test m.matched_data == UInt8[0x4d, 0x5a, 0x90, 0x00]
    end

    @testset "Multiple matches same pattern" begin
        data = UInt8[0x41, 0x42, 0x41, 0x42, 0x41, 0x42]
        rule = yara_rule("multi",
            strings = [yara_hex("ab", "41 42")],
            condition = :any_of_them)
        
        result = scan(rule, data)
        @test result.matched
        @test match_count(result) == 3
    end

    @testset "Empty data" begin
        data = UInt8[]
        rule = yara_rule("empty",
            strings = [yara_hex("sig", "4d 5a")],
            condition = :any_of_them)
        
        result = scan(rule, data)
        @test !result.matched
    end

    @testset "Tags and metadata preserved" begin
        rule = yara_rule("tagged",
            strings = [yara_text("t", "test")],
            condition = :any_of_them,
            tags = ["malware", "trojan"],
            metadata = Dict{String,Any}("severity" => 9, "family" => "test"))
        
        result = scan(rule, Vector{UInt8}("test data"))
        @test result.tags == ["malware", "trojan"]
        @test result.metadata["severity"] == 9
    end

    @testset "Wide string matching" begin
        # UTF-16LE encoded "AB"
        data = UInt8[0x41, 0x00, 0x42, 0x00]
        rule = yara_rule("wide_test",
            strings = [yara_text("w", "AB"; wide=true)],
            condition = :any_of_them)
        
        result = scan(rule, data)
        @test result.matched
    end
end
