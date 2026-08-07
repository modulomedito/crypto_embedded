-- Build modes
add_rules("mode.release", "mode.debug")

-- Shared library target (normal builds)
target("crypto_embedded")
set_kind("shared")
set_languages("c99", "c++17")
add_files("crypto_embedded/**.c")
add_headerfiles("crypto_embedded/**.h")
local includes = { ".", "crypto_embedded" }
for _, dir in ipairs(os.dirs("crypto_embedded/**")) do
    table.insert(includes, dir)
end
add_includedirs(includes)
if is_plat("windows") then
    set_runtimes("MT")
end

-- Standalone test binary (static link for coverage simplicity)
target("testsuite")
set_kind("binary")
set_languages("c99")
add_files("test/*.c")
add_files("test/unity/unity.c")
-- Statically compile crypto sources so gcov sees all code in one binary
add_files("crypto_embedded/**.c")
add_headerfiles("crypto_embedded/**.h")
add_includedirs(".", "crypto_embedded", "test", "test/unity")
add_defines("CRYPTO_NO_PANIC")
if is_plat("windows") then
    set_runtimes("MT")
end

-- Release mode optimizations
if is_mode("release") then
    if is_plat("windows") then
        add_cxflags("/O2", { force = true })
        add_ldflags("/INCREMENTAL:NO", { force = true })
    else
        set_optimize("fastest")
    end
end

-- Coverage mode: add profiling flags to testsuite (and library for completeness)
if is_mode("coverage") then
    add_cxflags("--coverage", { force = true })
    add_ldflags("--coverage", { force = true })
end

-- Phony test target for convenience
target("test")
set_kind("phony")
