#ifndef CSIFT_WINLOG_BINXML_HPP
#define CSIFT_WINLOG_BINXML_HPP

#include <map>
#include <string>
#include <vector>

#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "core/status.hpp"
#include "core/types.hpp"

namespace csift {
namespace winlog {

// Binary XML token identifiers (low 4 bits; bit 0x40 carries the "has more
// data" flag for element tokens). These mirror the real EVTX BinXML grammar.
enum class BinXmlToken : core::u8 {
    EndOfStream = 0x00,
    OpenStartElement = 0x01,
    CloseStartElement = 0x02,
    CloseEmptyElement = 0x03,
    EndElement = 0x04,
    Value = 0x05,
    Attribute = 0x06,
    CDataSection = 0x07,
    CharRef = 0x08,
    EntityRef = 0x09,
    PITarget = 0x0a,
    PIData = 0x0b,
    TemplateInstance = 0x0c,
    NormalSubstitution = 0x0d,
    OptionalSubstitution = 0x0e,
    FragmentHeader = 0x0f,
};

// Value-type identifiers used by Value tokens and substitution arrays.
enum class BinXmlValueType : core::u8 {
    Null = 0x00,
    StringType = 0x01,
    AnsiString = 0x02,
    Int8 = 0x03,
    UInt8 = 0x04,
    Int16 = 0x05,
    UInt16 = 0x06,
    Int32 = 0x07,
    UInt32 = 0x08,
    Int64 = 0x09,
    UInt64 = 0x0a,
    Real32 = 0x0b,
    Real64 = 0x0c,
    Bool = 0x0d,
    Binary = 0x0e,
    Guid = 0x0f,
    SizeT = 0x10,
    FileTime = 0x11,
    SysTime = 0x12,
    Sid = 0x13,
    HexInt32 = 0x14,
    HexInt64 = 0x15,
    BinXmlType = 0x21,
    ArrayFlag = 0x80,
};

// A flattened (name -> rendered value) pair produced from a record's BinXML.
// Element nesting is encoded into the dotted name (e.g. "EventData.Data.TargetUserName").
struct XmlField {
    std::string name;
    std::string value;
};

// The result of rendering one record's BinXML: the root element name plus all
// leaf fields discovered, in document order.
struct RenderedXml {
    std::string root_element;
    std::vector<XmlField> fields;

    // Convenience lookups for the fields the event mapper cares about.
    std::string get(const std::string& name) const;
    bool has(const std::string& name) const;
};

// Limits guarding the recursive token walk.
struct BinXmlLimits {
    core::usize max_depth = 64;
    core::usize max_fields = 4096;
    core::usize max_template_instances = 1024;
    core::usize max_string_chars = 1u << 16;
};

// Decodes the BinXML token stream in `binxml`, using `chunk` as the base for
// name and template offsets (which are chunk-relative in the real format).
// `diags` collects structural warnings. The decoder is bounds-checked and
// depth-limited; on malformed input it stops early and returns what it decoded.
RenderedXml decode_binxml(core::ByteSpan binxml, core::ByteSpan chunk,
                          core::DiagnosticSink& diags,
                          const BinXmlLimits& limits = BinXmlLimits());

}  // namespace winlog
}  // namespace csift

#endif  // CSIFT_WINLOG_BINXML_HPP
