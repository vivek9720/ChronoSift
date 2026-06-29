#ifndef CSIFT_TESTS_TEST_UTIL_HPP
#define CSIFT_TESTS_TEST_UTIL_HPP

#include <cstdio>
#include <cstdlib>
#include <string>

// A tiny self-contained check harness used by every ChronoSift test executable.
// It does not depend on assert()/NDEBUG: a failing CHECK prints the location and
// aborts with a non-zero exit so CTest records the failure deterministically.
namespace csift {
namespace test {

inline int& failure_count() {
    static int count = 0;
    return count;
}

inline void report(const char* file, int line, const char* expr) {
    std::fprintf(stderr, "CHECK FAILED: %s  (%s:%d)\n", expr, file, line);
    ++failure_count();
}

}  // namespace test
}  // namespace csift

#define CHECK(cond)                                              \
    do {                                                         \
        if (!(cond)) {                                           \
            ::csift::test::report(__FILE__, __LINE__, #cond);    \
        }                                                        \
    } while (0)

#define CHECK_EQ(a, b)                                                       \
    do {                                                                     \
        auto _va = (a);                                                      \
        auto _vb = (b);                                                      \
        if (!(_va == _vb)) {                                                 \
            ::csift::test::report(__FILE__, __LINE__, #a " == " #b);         \
        }                                                                    \
    } while (0)

#define RUN_TEST(fn)                               \
    do {                                           \
        std::printf("  - %s\n", #fn);              \
        fn();                                      \
    } while (0)

// Place at the end of main(): returns the process exit code.
#define TEST_MAIN_RESULT()                                          \
    (::csift::test::failure_count() == 0                            \
         ? (std::printf("OK\n"), 0)                                 \
         : (std::fprintf(stderr, "%d check(s) failed\n",            \
                         ::csift::test::failure_count()),           \
            1))

#endif  // CSIFT_TESTS_TEST_UTIL_HPP
