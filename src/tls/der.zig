const std = @import("std");
const io = std.io;
const meta = std.meta;
const mem = std.mem;
const Allocator = mem.Allocator;

pub const Identifier = enum(u8) {
    /// Simple types
    /// https://www.obj-sys.com/asn1tutorial/node10.html
    BOOLEAN = 1,
    INTEGER = 2,
    BIT_STRING = 3,
    OCTET_STRING = 4,
    NULL = 5,
    OBJECT_IDENTIFIER = 6,
    REAL = 9,
    ENUMERATED = 10,

    /// Structured types
    /// https://www.obj-sys.com/asn1tutorial/node11.html
    ///
    /// Note that the tag numbers enumerated here are different from ones of ASN.1.
    /// This is because these two are constructed types, so the bit 6 (3rd most significant bit)
    /// is set 1 in the DER format. See 8.1.2.2. and 8.1.2.5 of X.690 for more.
    SEQUENCE = (1 << 5) | 16,
    SET = (1 << 5) | 17,
};

/// The parser to decode a DER-formatted data as specified in X.690.
///
/// The specification can be found here:
/// https://www.itu.int/rec/T-REC-X.690-202102-I/en
pub const Parser = struct {
    /// Consume Identifier octets.
    ///
    /// `Tag`s can be found here:
    /// https://www.obj-sys.com/asn1tutorial/node9.html#SECTION00132000000000000000
    ///
    /// The bit 6 (3rd most significant bit) represents whether the encoding is primitive or
    /// constructed (as described in 8.1.2.5 in X.690), meaning that it is set to 1 if the
    /// tag is either SEQUENCE or SET.
    pub fn consumeIdentifier(reader: anytype) !Identifier {
        const byte = try reader.readByte();

        const id = try meta.intToEnum(Identifier, byte);
        return id;
    }

    /// Consume length octets.
    ///
    /// The indefinite form is not supported now.
    pub fn consumeLength(reader: anytype) !usize {
        const first = try reader.readByte();

        // If the bit 8 (the most significant bit) is 0, it's encoded in a short form.
        if ((first >> 7) == 0) {
            return first;
        }

        // In the long form, the initial octet must not be 0b1111_1111 according to 8.1.3.5 (c) of X.690.
        if (first == 0b1111_1111)
            return error.InvalidDER;

        const octets_len = first & 0b0111_1111;
        if (octets_len > @divExact(@typeInfo(usize).Int.bits, 8))
            return error.LengthTooLong;

        var octets = try std.heap.page_allocator.alloc(u8, octets_len);
        defer std.heap.page_allocator.free(octets);

        try reader.readNoEof(octets);

        return mem.readVarInt(usize, octets, .Big);
    }

    pub fn consumeInteger(reader: anytype) !i64 {
        const id = try consumeIdentifier(reader);
        if (id != .INTEGER)
            return error.InvalidIdentifier;

        const octets_len = try consumeLength(reader);

        var octets = try std.heap.page_allocator.alloc(u8, octets_len);
        defer std.heap.page_allocator.free(octets);

        try reader.readNoEof(octets);

        return mem.readVarInt(i64, octets, .Big);
    }

    pub fn consumeOctetString(allocator: Allocator, reader: anytype) ![]const u8 {
        const id = try consumeIdentifier(reader);
        if (id != .OCTET_STRING)
            return error.InvalidIdentifier;

        const octets_len = try consumeLength(reader);

        var ret = try allocator.alloc(u8, octets_len);
        errdefer allocator.free(ret);

        try reader.readNoEof(ret);
        return ret;
    }
};

test "consume SEQUENCE identifier" {
    var buf = [_]u8{@intFromEnum(Identifier.SEQUENCE)};
    var stream = io.fixedBufferStream(&buf);

    const id = try Parser.consumeIdentifier(stream.reader());
    try std.testing.expectEqual(Identifier.SEQUENCE, id);
}

test "consume length (short form)" {
    var buf = [_]u8{127};
    var stream = io.fixedBufferStream(&buf);

    const len = try Parser.consumeLength(stream.reader());
    try std.testing.expectEqual(@as(usize, 127), len);
}

test "consume length (long form)" {
    var buf = [_]u8{ 0b1000_0010, 0xff, 0xff };
    var stream = io.fixedBufferStream(&buf);

    const len = try Parser.consumeLength(stream.reader());
    try std.testing.expectEqual(@as(usize, 65535), len);
}

// TODO(magurotuna): add tests for consumeInteger and consumeOctetString
