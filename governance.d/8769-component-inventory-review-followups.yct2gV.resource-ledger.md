# Resource Ledger: 8769-component-inventory-review-followups.yct2gV

Range 32b3a1aa88..1921bd159b: the type-first rule for `component_inventory` `native` on all three legs and the header out-parameters of the shared ELF, Mach-O and PE readers. No new fd, handle, socket, allocation that outlives a call, thread, subprocess, shell string or temp path.

| ID | Construct | Owner | Lifetime | Failure behaviour |
|---|---|---|---|---|
| R1 | Out-parameters `header_type`, `thin_file_type`, `coff_characteristics` (borrowed pointers, default null) | the caller's local `std::optional` | written synchronously during the call, never stored | cleared on entry; set once the header is read |
| R2 | Lambdas `not_shared`, `not_dylib`, `not_dll` capturing the local optional by reference | the adapter frame | declared outside the `try`, used in the body and the `catch` | the optional outlives both |
| R3 | Per-slice `catch (...)` in `read_macho` | n/a | one slice | the failure becomes that slice's error; a stated file type is kept |
| R4 | `info.slices.reserve(nfat)` (`nfat` below 45) | `MachoInfo` value | returned to the caller | a failed reserve happens before any slice type is read |
