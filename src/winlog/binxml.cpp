#include "winlog/binxml.hpp"

#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "core/byte_reader.hpp"
#include "core/encoding.hpp"
#include "core/endian.hpp"
#include "core/string_util.hpp"
#include "winlog/evtx_header.hpp"

// BinXML decoder for the EVTX embedded Binary XML grammar. This implements a
// faithful subset: fragment headers, open/close/end element, attributes, inline
// string values, template instances with substitution arrays, and the two
// substitution tokens. Every read goes through core::ByteReader so it is
// bounds-checked; every loop makes forward progress or breaks; recursion is
// depth-limited and template offsets are tracked to defeat cyclic definitions.
//
// All offsets and lengths originate from untrusted input and are clamped to the
// actual span sizes before use. The decoder never reads out of bounds and
// always terminates.
namespace csift {
namespace winlog {

// ---------------------------------------------------------------------------
// RenderedXml lookups
// ---------------------------------------------------------------------------

std::string RenderedXml::get(const std::string& name) const {
    for (const XmlField& f : fields) {
        if (f.name == name) return f.value;
    }
    return std::string();
}

bool RenderedXml::has(const std::string& name) const {
    for (const XmlField& f : fields) {
        if (f.name == name) return true;
    }
    return false;
}

namespace {

// Token mask: the low 6 bits identify the token; 0x40 is the "has more data"
// flag carried by element-class tokens.
constexpr core::u8 kTokenMask = 0x3f;
constexpr core::u8 kMoreDataFlag = 0x40;

// Hard caps that protect against pathological inputs independent of the
// configurable BinXmlLimits (which a caller could set very high).
constexpr core::usize kAbsoluteTokenCap = 1u << 22;  // tokens walked per decode

// ---------------------------------------------------------------------------
// Decoder context
// ---------------------------------------------------------------------------

// One pending substitution value extracted from a template instance's value
// array. The type drives how the raw bytes are rendered to text.
struct SubValue {
    core::u8 type = 0;
    std::string text;  // already-rendered display text
};

// The shared state threaded through the recursive walk. `chunk` is the chunk
// origin used to resolve chunk-relative name and template-definition offsets.
struct DecodeCtx {
    core::ByteSpan chunk;
    core::DiagnosticSink& diags;
    const BinXmlLimits& limits;

    RenderedXml& out;

    // Element path stack: dotted names accumulate here as elements open.
    std::vector<std::string> path;

    // Offsets of template definitions currently being expanded, to break
    // self-referential / cyclic template chains.
    std::set<core::usize> active_templates;

    // Total template instances expanded (bounded by limits.max_template_instances).
    core::usize template_instances = 0;

    // Total tokens walked across the whole decode (bounded by kAbsoluteTokenCap).
    core::usize tokens_walked = 0;

    bool fields_full = false;  // latched once max_fields is reached

    DecodeCtx(core::ByteSpan c, core::DiagnosticSink& d, const BinXmlLimits& l,
              RenderedXml& o)
        : chunk(c), diags(d), limits(l), out(o) {}
};

// Join the current element path into a dotted name. Empty when at the root.
std::string current_path(const DecodeCtx& ctx) {
    std::string out;
    for (core::usize i = 0; i < ctx.path.size(); ++i) {
        if (i) out.push_back('.');
        out += ctx.path[i];
    }
    return out;
}

// Append a leaf field, honouring the max_fields cap. Returns false once the cap
// has been reached so callers can stop producing values.
bool add_field(DecodeCtx& ctx, const std::string& name, std::string value) {
    if (ctx.fields_full) return false;
    if (ctx.out.fields.size() >= ctx.limits.max_fields) {
        ctx.fields_full = true;
        ctx.diags.warn("winlog.binxml", "max_fields reached; truncating");
        return false;
    }
    XmlField f;
    f.name = name.empty() ? std::string("value") : name;
    f.value = std::move(value);
    ctx.out.fields.push_back(std::move(f));
    return true;
}

// ---------------------------------------------------------------------------
// Name reading
// ---------------------------------------------------------------------------

// Reads a NAME structure from an arbitrary span at the reader's current cursor.
// Layout: u32 unknown(next-name offset) ; u16 hash ; u16 num_chars ;
// num_chars UTF-16LE code units ; u16 NUL terminator. The character count is
// clamped to limits.max_string_chars and to the bytes actually available.
std::string read_name_from_reader(core::ByteReader& r, const BinXmlLimits& limits) {
    r.read_u32_le();  // next-name offset hint (ignored)
    r.read_u16_le();  // name hash (ignored)
    core::u32 num_chars = r.read_u16_le();
    if (r.error()) return std::string();

    core::usize chars = num_chars;
    if (chars > limits.max_string_chars) chars = limits.max_string_chars;
    core::usize avail_units = r.remaining() / 2;
    if (chars > avail_units) chars = avail_units;

    core::ByteSpan raw = r.read_bytes(chars * 2);
    std::string name = core::utf16le_to_utf8(raw, chars);

    // Consume the u16 NUL terminator if present (best effort; ignore underflow).
    r.read_u16_le();
    return name;
}

// Reads a NAME located at a chunk-relative offset. Used when an element or
// attribute name is encoded as an offset into the chunk's name table.
std::string read_name_at(const DecodeCtx& ctx, core::usize offset) {
    if (offset >= ctx.chunk.size()) return std::string();
    core::ByteReader r(ctx.chunk.from(offset));
    return read_name_from_reader(r, ctx.limits);
}

// Reads an element/attribute name given a reader positioned where a name
// reference appears. In the real format a name is a u32 chunk offset; when that
// offset equals the reader's current absolute position the name is stored
// inline immediately after. We support both: resolve the offset into the chunk,
// and if it points at or past the chunk end fall back to an inline read.
//
// `binxml_base` is the offset of the binxml span within the chunk so we can map
// the reader's local position to an absolute chunk position when needed.
std::string read_name_ref(DecodeCtx& ctx, core::ByteReader& r,
                          core::usize binxml_base) {
    core::usize ref_local_pos = r.position();
    core::u32 name_offset = r.read_u32_le();
    if (r.error()) return std::string();

    // If the name offset points at the reference site itself, the name is
    // inline (continue reading from the current reader, which is now just past
    // the 4-byte offset, i.e. at the start of the inline NAME body).
    core::usize ref_abs = binxml_base + ref_local_pos;
    if (name_offset == ref_abs) {
        // Inline: re-read the NAME body starting from the current reader pos.
        // The 4-byte offset we just consumed IS the NAME's leading u32, so back
        // up to it and parse the whole NAME structure inline.
        r.seek(ref_local_pos);
        return read_name_from_reader(r, ctx.limits);
    }

    // Otherwise the name lives elsewhere in the chunk.
    if (name_offset < ctx.chunk.size()) {
        return read_name_at(ctx, name_offset);
    }

    // Out-of-range offset: treat the bytes we already consumed as the start of
    // an inline name to stay robust, but only if there is room.
    r.seek(ref_local_pos);
    return read_name_from_reader(r, ctx.limits);
}

// ---------------------------------------------------------------------------
// Value rendering
// ---------------------------------------------------------------------------

std::string render_guid(core::ByteSpan b) {
    if (b.size() < 16) return std::string();
    char buf[64];
    core::u32 d1 = core::load_u32_le(b.data());
    core::u16 d2 = core::load_u16_le(b.data() + 4);
    core::u16 d3 = core::load_u16_le(b.data() + 6);
    std::snprintf(buf, sizeof(buf),
                  "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", d1, d2, d3,
                  b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return std::string(buf);
}

// Renders a Windows SID (S-1-...). Layout: u8 revision; u8 sub-authority count;
// 6-byte authority (big-endian); then count u32 LE sub-authorities.
std::string render_sid(core::ByteSpan b) {
    if (b.size() < 8) return std::string();
    core::u8 rev = b[0];
    core::u8 count = b[1];
    core::u64 authority = 0;
    for (int i = 0; i < 6; ++i) authority = (authority << 8) | b[2 + i];
    std::string out = "S-" + std::to_string(rev) + "-" + std::to_string(authority);
    core::usize need = 8 + static_cast<core::usize>(count) * 4;
    if (need > b.size()) {
        core::usize avail = (b.size() > 8) ? (b.size() - 8) / 4 : 0;
        count = static_cast<core::u8>(avail);
    }
    for (core::u8 i = 0; i < count; ++i) {
        core::u32 sub = core::load_u32_le(b.data() + 8 + i * 4);
        out += "-" + std::to_string(sub);
    }
    return out;
}

// Renders a raw value blob according to its BinXML value type into display
// text. Unknown / structured types fall back to a hex dump. Never reads OOB.
std::string render_value(core::u8 type, core::ByteSpan b,
                         const BinXmlLimits& limits) {
    // Strip the array flag for the scalar render path.
    core::u8 base = type & 0x7f;
    switch (static_cast<BinXmlValueType>(base)) {
        case BinXmlValueType::Null:
            return std::string();
        case BinXmlValueType::StringType: {
            core::usize units = b.size() / 2;
            if (units > limits.max_string_chars) units = limits.max_string_chars;
            return core::utf16le_to_utf8(b, units);
        }
        case BinXmlValueType::AnsiString: {
            // Latin1-ish; strip a trailing NUL if present.
            std::string s = b.to_string();
            while (!s.empty() && s.back() == '\0') s.pop_back();
            return s;
        }
        case BinXmlValueType::Int8:
            return b.size() >= 1 ? std::to_string(static_cast<core::i8>(b[0]))
                                 : std::string();
        case BinXmlValueType::UInt8:
            return b.size() >= 1 ? std::to_string(static_cast<unsigned>(b[0]))
                                 : std::string();
        case BinXmlValueType::Int16:
            return b.size() >= 2
                       ? std::to_string(static_cast<core::i16>(core::load_u16_le(b.data())))
                       : std::string();
        case BinXmlValueType::UInt16:
            return b.size() >= 2 ? std::to_string(core::load_u16_le(b.data()))
                                 : std::string();
        case BinXmlValueType::Int32:
            return b.size() >= 4
                       ? std::to_string(static_cast<core::i32>(core::load_u32_le(b.data())))
                       : std::string();
        case BinXmlValueType::UInt32:
            return b.size() >= 4 ? std::to_string(core::load_u32_le(b.data()))
                                 : std::string();
        case BinXmlValueType::Int64:
            return b.size() >= 8
                       ? std::to_string(static_cast<core::i64>(core::load_u64_le(b.data())))
                       : std::string();
        case BinXmlValueType::UInt64:
        case BinXmlValueType::SizeT:
            return b.size() >= 8 ? std::to_string(core::load_u64_le(b.data()))
                                 : std::string();
        case BinXmlValueType::Real32: {
            if (b.size() < 4) return std::string();
            core::u32 bits = core::load_u32_le(b.data());
            float f;
            std::memcpy(&f, &bits, sizeof(f));
            return std::to_string(f);
        }
        case BinXmlValueType::Real64: {
            if (b.size() < 8) return std::string();
            core::u64 bits = core::load_u64_le(b.data());
            double d;
            std::memcpy(&d, &bits, sizeof(d));
            return std::to_string(d);
        }
        case BinXmlValueType::Bool: {
            if (b.size() < 1) return std::string();
            core::u32 v = (b.size() >= 4) ? core::load_u32_le(b.data()) : b[0];
            return v ? "true" : "false";
        }
        case BinXmlValueType::Guid:
            return render_guid(b);
        case BinXmlValueType::FileTime:
            // Rendered as the raw 100ns count; the event mapper handles the
            // semantic conversion only for the record's own filetime field.
            return b.size() >= 8 ? std::to_string(core::load_u64_le(b.data()))
                                 : std::string();
        case BinXmlValueType::SysTime: {
            // SYSTEMTIME: 8 u16 fields (year,month,dow,day,hour,min,sec,ms).
            if (b.size() < 16) return std::string();
            core::u16 y = core::load_u16_le(b.data());
            core::u16 mo = core::load_u16_le(b.data() + 2);
            core::u16 d = core::load_u16_le(b.data() + 6);
            core::u16 h = core::load_u16_le(b.data() + 8);
            core::u16 mi = core::load_u16_le(b.data() + 10);
            core::u16 s = core::load_u16_le(b.data() + 12);
            char buf[40];
            std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02u", y,
                          mo, d, h, mi, s);
            return std::string(buf);
        }
        case BinXmlValueType::Sid:
            return render_sid(b);
        case BinXmlValueType::HexInt32: {
            if (b.size() < 4) return std::string();
            char buf[16];
            std::snprintf(buf, sizeof(buf), "0x%x", core::load_u32_le(b.data()));
            return std::string(buf);
        }
        case BinXmlValueType::HexInt64: {
            if (b.size() < 8) return std::string();
            char buf[24];
            std::snprintf(buf, sizeof(buf), "0x%llx",
                          static_cast<unsigned long long>(core::load_u64_le(b.data())));
            return std::string(buf);
        }
        case BinXmlValueType::Binary:
        case BinXmlValueType::BinXmlType:
        default: {
            // Unknown/structured: hex dump, bounded so a huge blob cannot blow
            // up memory in the rendered field.
            core::usize cap = b.size();
            if (cap > limits.max_string_chars) cap = limits.max_string_chars;
            return core::to_hex(b.first(cap));
        }
    }
}

// ---------------------------------------------------------------------------
// Forward declarations for the mutually recursive walk
// ---------------------------------------------------------------------------

// Walks a BinXML fragment. `binxml` is the fragment bytes; `binxml_base` is the
// fragment's offset within the chunk (for inline-name resolution). `subs` is
// the active substitution array (empty when not inside a template), and `depth`
// bounds recursion. Returns when EndOfStream/EndElement closes the fragment or
// the bytes run out.
void walk_fragment(DecodeCtx& ctx, core::ByteSpan binxml, core::usize binxml_base,
                   const std::vector<SubValue>* subs, core::usize depth);

// Expands a template instance found at the reader's current position.
void expand_template(DecodeCtx& ctx, core::ByteReader& r, core::usize binxml_base,
                     core::usize depth);

// ---------------------------------------------------------------------------
// Substitution-array parsing for template instances
// ---------------------------------------------------------------------------

// Reads the substitution descriptor + value arrays that follow a template
// definition. Layout: u32 num_substitutions ; num entries of
// (u16 size, u8 type, u8 reserved) ; then the raw values back-to-back, each
// `size` bytes, decoded per type. All counts/sizes are clamped to the reader's
// remaining bytes. Returns the rendered values.
std::vector<SubValue> read_substitutions(DecodeCtx& ctx, core::ByteReader& r) {
    std::vector<SubValue> values;
    core::u32 count = r.read_u32_le();
    if (r.error()) return values;

    // Bound the descriptor count: each descriptor is 4 bytes, so it cannot
    // exceed remaining/4, and never more than max_fields to bound memory.
    core::usize max_by_bytes = r.remaining() / 4;
    if (count > max_by_bytes) count = static_cast<core::u32>(max_by_bytes);
    core::usize cap = ctx.limits.max_fields;
    if (count > cap) count = static_cast<core::u32>(cap);

    struct Desc {
        core::u16 size;
        core::u8 type;
    };
    std::vector<Desc> descs;
    descs.reserve(count);
    for (core::u32 i = 0; i < count; ++i) {
        core::u16 sz = r.read_u16_le();
        core::u8 ty = r.read_u8();
        r.read_u8();  // reserved
        if (r.error()) break;
        descs.push_back(Desc{sz, ty});
    }

    values.reserve(descs.size());
    for (const Desc& d : descs) {
        // Clamp the value size to the bytes actually remaining so a lying size
        // cannot drive an over-read.
        core::usize sz = d.size;
        if (sz > r.remaining()) sz = r.remaining();
        core::ByteSpan raw = r.read_bytes(sz);
        SubValue v;
        v.type = d.type;
        v.text = render_value(d.type, raw, ctx.limits);
        values.push_back(std::move(v));
        if (r.error()) break;
    }
    return values;
}

// ---------------------------------------------------------------------------
// Template expansion
// ---------------------------------------------------------------------------

void expand_template(DecodeCtx& ctx, core::ByteReader& r, core::usize binxml_base,
                     core::usize depth) {
    (void)binxml_base;
    // TemplateInstance body: u8 version/unknown ; u32 template_id ;
    // u32 template_definition_data_offset (chunk-relative).
    r.read_u8();                      // version / unknown
    r.read_u32_le();                  // template id (ignored for rendering)
    core::u32 def_offset = r.read_u32_le();
    if (r.error()) return;

    if (++ctx.template_instances > ctx.limits.max_template_instances) {
        ctx.diags.warn("winlog.binxml", "max_template_instances reached");
        return;
    }
    if (depth >= ctx.limits.max_depth) {
        ctx.diags.warn("winlog.binxml", "max_depth reached in template");
        return;
    }

    // Resolve the template definition within the chunk.
    if (def_offset >= ctx.chunk.size()) {
        ctx.diags.warn("winlog.binxml", "template offset out of range");
        // Still read the substitution array that follows so the outer cursor
        // stays consistent, then bail without rendering.
        read_substitutions(ctx, r);
        return;
    }

    // Cycle guard: refuse to re-enter a definition we're already expanding.
    if (ctx.active_templates.count(def_offset)) {
        ctx.diags.warn("winlog.binxml", "cyclic template definition");
        read_substitutions(ctx, r);
        return;
    }

    // Parse the template definition header at def_offset within the chunk:
    // u32 next_offset ; GUID(16) ; u32 data_size ; then the template BinXML.
    core::ByteReader dr(ctx.chunk.from(def_offset));
    dr.read_u32_le();           // next template offset (unused)
    dr.read_bytes(16);          // template GUID (unused)
    core::u32 data_size = dr.read_u32_le();
    if (dr.error()) {
        ctx.diags.warn("winlog.binxml", "truncated template definition");
        read_substitutions(ctx, r);
        return;
    }

    // The template BinXML body starts right after this 24-byte def header.
    core::usize body_local = dr.position();          // within dr's span
    core::usize body_abs = def_offset + body_local;  // within the chunk
    core::usize avail = dr.remaining();
    core::usize body_len = data_size;
    if (body_len > avail) body_len = avail;
    core::ByteSpan body = dr.read_bytes(body_len);

    // Read the substitution array that follows the *instance* (in the outer
    // stream), then render the definition body against it.
    std::vector<SubValue> subs = read_substitutions(ctx, r);

    ctx.active_templates.insert(def_offset);
    walk_fragment(ctx, body, body_abs, &subs, depth + 1);
    ctx.active_templates.erase(def_offset);
}

// ---------------------------------------------------------------------------
// Inline value token reading
// ---------------------------------------------------------------------------

// Handles a Value (0x05/0x45) token's payload: u8 value_type then, for the
// common StringType, u16 num_chars followed by that many UTF-16LE units. Emits
// the rendered text as a leaf field at the current element path.
void handle_value_token(DecodeCtx& ctx, core::ByteReader& r) {
    core::u8 vtype = r.read_u8();
    if (r.error()) return;

    if ((vtype & 0x7f) == static_cast<core::u8>(BinXmlValueType::StringType)) {
        core::u32 num_chars = r.read_u16_le();
        if (r.error()) return;
        core::usize chars = num_chars;
        if (chars > ctx.limits.max_string_chars) chars = ctx.limits.max_string_chars;
        core::usize avail_units = r.remaining() / 2;
        if (chars > avail_units) chars = avail_units;
        core::ByteSpan raw = r.read_bytes(chars * 2);
        std::string text = core::utf16le_to_utf8(raw, chars);
        add_field(ctx, current_path(ctx), std::move(text));
        return;
    }

    // Other inline value types are rare in records (most data is template
    // substitutions). Render best-effort using a heuristic fixed width or skip.
    // We do not know the byte length of arbitrary inline types here, so we emit
    // an empty placeholder to keep the cursor aligned to the token boundary.
    add_field(ctx, current_path(ctx), std::string());
}

// ---------------------------------------------------------------------------
// Attribute reading
// ---------------------------------------------------------------------------

// Handles an Attribute (0x06) token: a Name follows, and the immediately
// following Value/Substitution token supplies the attribute's value. We read
// the name, then peek the next token to grab its value, recording the pair as
// "<elementpath>@<attrname>".
void handle_attribute(DecodeCtx& ctx, core::ByteReader& r, core::usize binxml_base,
                      const std::vector<SubValue>* subs) {
    std::string attr_name = read_name_ref(ctx, r, binxml_base);
    if (r.error()) return;

    std::string base = current_path(ctx);
    std::string field_name = base + "@" + attr_name;

    // The value-bearing token follows. Inspect it.
    core::u8 next = r.peek_u8();
    if (r.error()) return;
    core::u8 tk = next & kTokenMask;

    if (tk == static_cast<core::u8>(BinXmlToken::Value)) {
        r.read_u8();  // consume the token byte
        core::u8 vtype = r.read_u8();
        if ((vtype & 0x7f) == static_cast<core::u8>(BinXmlValueType::StringType)) {
            core::u32 num_chars = r.read_u16_le();
            core::usize chars = num_chars;
            if (chars > ctx.limits.max_string_chars) chars = ctx.limits.max_string_chars;
            core::usize avail_units = r.remaining() / 2;
            if (chars > avail_units) chars = avail_units;
            core::ByteSpan raw = r.read_bytes(chars * 2);
            add_field(ctx, field_name, core::utf16le_to_utf8(raw, chars));
        } else {
            add_field(ctx, field_name, std::string());
        }
    } else if (tk == static_cast<core::u8>(BinXmlToken::NormalSubstitution) ||
               tk == static_cast<core::u8>(BinXmlToken::OptionalSubstitution)) {
        r.read_u8();  // consume token byte
        core::u16 idx = r.read_u16_le();
        r.read_u8();  // value type
        std::string val;
        if (subs && idx < subs->size()) val = (*subs)[idx].text;
        add_field(ctx, field_name, std::move(val));
    } else {
        // No recognised value token; record an empty attribute and let the main
        // loop process whatever comes next.
        add_field(ctx, field_name, std::string());
    }
}

// ---------------------------------------------------------------------------
// Element opening
// ---------------------------------------------------------------------------

// Handles an OpenStartElement (0x01/0x41) token. Robust layout used here:
// u16 dependency_id ; u32 data_size ; Name(element). The element name is pushed
// onto the path stack (bounded by max_depth). data_size is informational; we do
// not use it to jump because the token stream itself drives termination.
void handle_open_element(DecodeCtx& ctx, core::ByteReader& r, core::usize binxml_base,
                         bool has_more) {
    (void)has_more;
    r.read_u16_le();   // dependency identifier
    r.read_u32_le();   // data size (bytes of element content; advisory)
    std::string name = read_name_ref(ctx, r, binxml_base);
    if (r.error()) return;

    if (ctx.path.size() < ctx.limits.max_depth) {
        ctx.path.push_back(name);
        if (ctx.out.root_element.empty()) ctx.out.root_element = name;
    } else {
        ctx.diags.warn("winlog.binxml", "max_depth reached opening element");
    }
}

// ---------------------------------------------------------------------------
// Main token walk
// ---------------------------------------------------------------------------

void walk_fragment(DecodeCtx& ctx, core::ByteSpan binxml, core::usize binxml_base,
                   const std::vector<SubValue>* subs, core::usize depth) {
    if (depth >= ctx.limits.max_depth) {
        ctx.diags.warn("winlog.binxml", "max_depth reached in fragment");
        return;
    }

    core::ByteReader r(binxml);

    // Track how many elements this fragment opened so we can pop them on exit
    // and keep the path stack balanced even on malformed input.
    core::usize opened_here = 0;

    while (!r.error() && r.remaining() > 0) {
        if (++ctx.tokens_walked > kAbsoluteTokenCap) {
            ctx.diags.warn("winlog.binxml", "token cap reached");
            break;
        }
        if (ctx.fields_full) {
            // We will not emit more fields; stop walking to save work, but keep
            // the path balanced below.
            break;
        }

        core::usize before = r.position();
        core::u8 raw_tok = r.read_u8();
        if (r.error()) break;
        core::u8 tok = raw_tok & kTokenMask;
        bool has_more = (raw_tok & kMoreDataFlag) != 0;

        switch (static_cast<BinXmlToken>(tok)) {
            case BinXmlToken::EndOfStream:
                // End of this fragment.
                goto done;

            case BinXmlToken::FragmentHeader:
                r.read_u8();  // major
                r.read_u8();  // minor
                r.read_u8();  // flags
                break;

            case BinXmlToken::OpenStartElement: {
                core::usize before_open = ctx.path.size();
                handle_open_element(ctx, r, binxml_base, has_more);
                if (ctx.path.size() > before_open) ++opened_here;
                break;
            }

            case BinXmlToken::Attribute:
                handle_attribute(ctx, r, binxml_base, subs);
                break;

            case BinXmlToken::CloseStartElement:
                // Element content begins; nothing to do.
                break;

            case BinXmlToken::CloseEmptyElement:
                // Self-closing element: pop it now.
                if (opened_here > 0 && !ctx.path.empty()) {
                    ctx.path.pop_back();
                    --opened_here;
                }
                break;

            case BinXmlToken::EndElement:
                if (opened_here > 0 && !ctx.path.empty()) {
                    ctx.path.pop_back();
                    --opened_here;
                }
                break;

            case BinXmlToken::Value:
                handle_value_token(ctx, r);
                break;

            case BinXmlToken::CDataSection: {
                // u16 num_chars, then UTF-16LE chars.
                core::u32 n = r.read_u16_le();
                core::usize chars = n;
                if (chars > ctx.limits.max_string_chars) chars = ctx.limits.max_string_chars;
                core::usize avail_units = r.remaining() / 2;
                if (chars > avail_units) chars = avail_units;
                core::ByteSpan raw = r.read_bytes(chars * 2);
                add_field(ctx, current_path(ctx), core::utf16le_to_utf8(raw, chars));
                break;
            }

            case BinXmlToken::CharRef:
                r.read_u16_le();  // unicode code point reference
                break;

            case BinXmlToken::EntityRef:
                // Name reference to a predefined entity.
                read_name_ref(ctx, r, binxml_base);
                break;

            case BinXmlToken::PITarget:
                read_name_ref(ctx, r, binxml_base);
                break;

            case BinXmlToken::PIData: {
                core::u32 n = r.read_u16_le();
                core::usize chars = n;
                core::usize avail_units = r.remaining() / 2;
                if (chars > avail_units) chars = avail_units;
                r.read_bytes(chars * 2);
                break;
            }

            case BinXmlToken::TemplateInstance:
                expand_template(ctx, r, binxml_base, depth);
                break;

            case BinXmlToken::NormalSubstitution:
            case BinXmlToken::OptionalSubstitution: {
                core::u16 idx = r.read_u16_le();
                r.read_u8();  // value type
                if (r.error()) break;
                std::string val;
                if (subs && idx < subs->size()) {
                    val = (*subs)[idx].text;
                }
                // Emit the substituted value at the current element path. For
                // OptionalSubstitution an empty value is still recorded as an
                // empty leaf, matching how the XML would render <Tag/>.
                add_field(ctx, current_path(ctx), std::move(val));
                break;
            }

            default:
                // Unknown token: we cannot know its length. Recording the
                // position lets the forward-progress guard below break the loop
                // rather than spin.
                ctx.diags.warn("winlog.binxml", "unknown BinXML token");
                goto done;
        }

        // Forward-progress guard: if a handler consumed nothing (e.g. a
        // self-referential inline name that seeked back), break to guarantee
        // termination.
        if (r.position() <= before) {
            ctx.diags.warn("winlog.binxml", "no forward progress; stopping");
            break;
        }
    }

done:
    // Pop any elements this fragment left open so the caller's path stack stays
    // balanced (important for nested template fragments).
    while (opened_here > 0 && !ctx.path.empty()) {
        ctx.path.pop_back();
        --opened_here;
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

RenderedXml decode_binxml(core::ByteSpan binxml, core::ByteSpan chunk,
                          core::DiagnosticSink& diags, const BinXmlLimits& limits) {
    RenderedXml out;
    if (binxml.empty()) return out;

    DecodeCtx ctx(chunk, diags, limits, out);

    // The BinXML span lives inside the chunk; compute its base offset so inline
    // name references (which use absolute chunk offsets) resolve correctly. If
    // the span is not actually inside the chunk (e.g. a synthetic test span),
    // fall back to base 0, which still keeps inline detection self-consistent.
    core::usize binxml_base = 0;
    if (chunk.data() && binxml.data() && binxml.data() >= chunk.data() &&
        binxml.data() <= chunk.data() + chunk.size()) {
        binxml_base = static_cast<core::usize>(binxml.data() - chunk.data());
    }

    walk_fragment(ctx, binxml, binxml_base, /*subs=*/nullptr, /*depth=*/0);
    return out;
}

}  // namespace winlog
}  // namespace csift
