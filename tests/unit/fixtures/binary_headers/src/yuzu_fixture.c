/* Fixture source for the binary-header readers: one exported function, nothing else.
 * Built by ../capture.sh into the PE, ELF and Mach-O fixtures. */

#if defined(_WIN32)
#define YUZU_FIXTURE_EXPORT __declspec(dllexport)
#else
#define YUZU_FIXTURE_EXPORT __attribute__((visibility("default")))
#endif

YUZU_FIXTURE_EXPORT int yuzu_fixture_value(void) {
    return 42;
}
