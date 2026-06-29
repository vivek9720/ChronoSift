#include <string>

#include "core/byte_reader.hpp"
#include "core/byte_span.hpp"
#include "core/encoding.hpp"
#include "core/string_util.hpp"
#include "core/time_util.hpp"
#include "test_util.hpp"

using namespace csift::core;

static void test_byte_span_bounds() {
    const byte data[] = {1, 2, 3, 4, 5};
    ByteSpan s(data, 5);
    CHECK_EQ(s.size(), static_cast<usize>(5));
    CHECK_EQ(s.at(0), static_cast<byte>(1));
    CHECK_EQ(s.at(99), static_cast<byte>(0));  // out of range -> 0
    ByteSpan sub = s.subspan(2, 10);           // clipped
    CHECK_EQ(sub.size(), static_cast<usize>(3));
    CHECK_EQ(sub.at(0), static_cast<byte>(3));
    ByteSpan none = s.subspan(99, 1);
    CHECK(none.empty());
    CHECK(s.starts_with("\x01\x02"));
    CHECK(!s.starts_with("\x02"));
}

static void test_byte_reader_underflow() {
    const byte data[] = {0x01, 0x02, 0x03};
    ByteReader r(ByteSpan(data, 3));
    CHECK_EQ(r.read_u8(), static_cast<u8>(1));
    CHECK_EQ(r.read_u16_le(), static_cast<u16>(0x0302));
    CHECK(!r.error());
    (void)r.read_u8();      // underflow now
    CHECK(r.error());
    CHECK_EQ(r.read_u32_le(), static_cast<u32>(0));  // stays safe
}

static void test_string_util() {
    CHECK_EQ(to_lower("AbC"), std::string("abc"));
    CHECK(starts_with("hello", "he"));
    CHECK(ends_with("hello", "lo"));
    CHECK(!ends_with("hi", "hello"));
    std::vector<std::string> parts = split("a,b,,c", ',');
    CHECK_EQ(parts.size(), static_cast<usize>(4));
    CHECK_EQ(parts[2], std::string());
    std::vector<std::string> ws = split_whitespace("  a   b\tc ");
    CHECK_EQ(ws.size(), static_cast<usize>(3));
    std::vector<std::string> lines = split_lines("a\r\nb\nc");
    CHECK_EQ(lines.size(), static_cast<usize>(3));
    CHECK_EQ(lines[0], std::string("a"));
    u64 v = 0;
    CHECK(parse_u64("12345", v));
    CHECK_EQ(v, static_cast<u64>(12345));
    CHECK(!parse_u64("12a", v));
    CHECK(!parse_u64("99999999999999999999999999", v));  // overflow
    i64 sv = 0;
    CHECK(parse_i64("-42", sv));
    CHECK_EQ(sv, static_cast<i64>(-42));
}

static void test_encoding() {
    CHECK_EQ(to_hex(std::string("\x01\xff", 2)), std::string("01ff"));
    Result<std::string> h = from_hex("48656c6c6f");
    CHECK(h.ok());
    CHECK_EQ(h.value(), std::string("Hello"));
    CHECK(!from_hex("xyz").ok());
    CHECK(!from_hex("abc").ok());  // odd length
    CHECK_EQ(percent_decode("a%20b%2Fc"), std::string("a b/c"));
    Result<std::string> b = base64_decode("SGVsbG8=");
    CHECK(b.ok());
    CHECK_EQ(b.value(), std::string("Hello"));
    CHECK(!base64_decode("@@@@").ok());
    usize cps = 0;
    CHECK(is_valid_utf8(ByteSpan::from_string("hello"), &cps));
    CHECK_EQ(cps, static_cast<usize>(5));
    const byte bad[] = {0xff, 0xfe};
    CHECK(!is_valid_utf8(ByteSpan(bad, 2)));
    // UTF-16LE "Hi" = 48 00 69 00
    const byte u16[] = {0x48, 0x00, 0x69, 0x00};
    CHECK_EQ(utf16le_to_utf8(ByteSpan(u16, 4), 2), std::string("Hi"));
}

static void test_time() {
    Timestamp t = parse_iso8601("2024-03-09T11:22:33.456789Z");
    CHECK(t.valid);
    CivilTime c = civil_from_micros(t.micros);
    CHECK_EQ(c.year, 2024);
    CHECK_EQ(static_cast<int>(c.month), 3);
    CHECK_EQ(static_cast<int>(c.day), 9);
    CHECK_EQ(static_cast<int>(c.hour), 11);
    CHECK_EQ(t.to_iso8601(), std::string("2024-03-09T11:22:33.456789Z"));
    // round trip
    CivilTime in{2000, 2, 29, 23, 59, 59, 0};  // leap day
    CHECK(is_leap_year(2000));
    i64 m = micros_from_civil(in);
    CivilTime out = civil_from_micros(m);
    CHECK_EQ(out.year, 2000);
    CHECK_EQ(static_cast<int>(out.day), 29);
    // offset handling
    Timestamp z = parse_iso8601("2024-01-01T00:00:00+02:00");
    Timestamp u = parse_iso8601("2023-12-31T22:00:00Z");
    CHECK(z.valid && u.valid);
    CHECK_EQ(z.micros, u.micros);
    // invalid
    CHECK(!parse_iso8601("not-a-time").valid);
    Timestamp clf = parse_clf_time("[10/Oct/2000:13:55:36 -0700]");
    CHECK(clf.valid);
}

int main() {
    std::printf("core_tests\n");
    RUN_TEST(test_byte_span_bounds);
    RUN_TEST(test_byte_reader_underflow);
    RUN_TEST(test_string_util);
    RUN_TEST(test_encoding);
    RUN_TEST(test_time);
    return TEST_MAIN_RESULT();
}
