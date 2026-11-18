# Resource Ledger — #7040 device_ci cpu/dimm pipe split (option C)

Range: `ac214d5393..687a7d157e` (branch `fix/7040-device-ci-pipe-split`)

## Summary

This diff adds **no thread, subprocess, socket, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt handle, mapped
library, temp path, file descriptor or callback context, and no manual cleanup.** Every C++ change is
`std::string` / `std::string_view` / `std::vector<std::string>` value manipulation. Independently proven by
cpp-safety at Gate 3 and again at Gate 8 (including a 200,000-string ASan/UBSan fuzz of both splitters and a round
trip through the new row builder).

## Table 1: changed or new constructs

| ID | Construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `split_pipe(line, true)` tokens in `build_device_ci_record` (cpu and dimm loops) | `std::vector<std::string_view>` local to the loop body, views into `out.processors` / `out.memory` (`const CiPluginOutputs&`, outlive the function) | per line | end of the loop iteration | none | nothing owned; `to_ll` consumes the view immediately |
| R2 | `rec.cpu_model = unescape_pipes(t[2])` | owning `std::string` returned by value | in the loop | owned by `CiRecord` | moved into the record | RAII |
| R3 | `format_cpu_row_sampled(...)` result (Linux and macOS legs) | owning `std::string` built with `std::format`; `safe_output_field(model)` temporary lives to the end of the full expression | per call | consumed by `ctx.write_output` | none | RAII; no view of `model` is retained (the macOS call passes `std::string_view{brand}` of a local that outlives the call) |
| R4 | `parse_dmidecode_memory` slot / type / speed escaping | local `std::string` copies and `safe_output_field` temporaries concatenated into the row | per DIMM | row owned by `rows` | none | RAII |
| R5 | `LiveKind::escaped_rows` (new `bool` member) and `lk.escaped_rows ? split_all_pipes(l) : pipe_fields(l)` | value member; both arms return `std::vector<std::string>` by value | per request line | end of the loop body | `std::move` into `rows` | RAII; the row count stays bounded by `kMaxLiveRows` and the width by `f.resize(lk.columns.size())`, both unchanged |
| R6 | New lexical test reads `hardware_plugin.cpp` | `std::ifstream` (RAII) in a test-only scope | test start | scope exit | none | RAII |

## Table 2: raw resource APIs touched

None.
