# Resource Ledger: fix-sw-ui-found-by-chips

Every owning boundary the diff adds or changes in C++ (server/core/src/software_catalog_rules.hpp, server/core/src/inventory_ui.cpp and their unit tests).

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `kSoftwareKinds`, `kSoftwareSources` | `inline constexpr std::array<VocabEntry, N>` of `string_view` into string literals | static storage | program exit | none | none needed; `vocab_table_well_formed` rejects a malformed table at compile time |
| R2 | `chips_region` local `std::vector<Chip>` rows | the vector, built per request | filled from the tables | scope exit | none | RAII; copies strings only |

No manual resource cleanup, thread, descriptor, socket, `FILE*`, SQLite handle or callback is added.
