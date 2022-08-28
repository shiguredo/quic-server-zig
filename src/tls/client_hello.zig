const std = @import("std");
const math = std.math;
const mem = std.mem;
const VariableLengthVector = @import("../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../bytes.zig").Bytes;

/// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.3.1
///
/// uint16 ProtocolVersion;
/// opaque Random[32];
///
/// uint8 CipherSuite[2];    /* Cryptographic suite selector */
///
/// struct {
///      ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///      Random random;
///      opaque legacy_session_id<0..32>;
///      CipherSuite cipher_suites<2..2^16-2>;
///      opaque legacy_compression_methods<1..2^8-1>;
///      Extension extensions<8..2^16-1>;
/// } ClientHello;
pub const ClientHello = struct {
    const legacy_version = 0x0303;
    const ProtocolVersion = u16;
    const Random = [32]u8;
    const LegacySessionId = VariableLengthVector(u8, u32);
    const CipherSuite = [2]u8;
    const CipherSuites = VariableLengthVector(CipherSuite, 255);
    const LegacyCompressionMethods = VariableLengthVector(u8, 255);
    const Extensions = VariableLengthVector(Extension, 65535);

    legacy_version: u16 = legacy_version,
    random: [32]u8,
    legacy_session_id: VariableLengthVector(u8, 32),
    cipher_suites: CipherSuites,
    legacy_compression_methods: LegacyCompressionMethods,
    extensions: Extensions,

    pub fn encodedLength(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(ProtocolVersion);
        len += @sizeOf(Random);
        len += self.legacy_session_id.encodedLength();
        len += self.cipher_suites.encodedLength();
        len += self.legacy_compression_methods.encodedLength();
        len += self.extensions.encodedLength();
        return len;
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.put(u16, self.legacy_version);
        try out.putBytes(&self.random);
        try self.legacy_session_id.encode(out);
        try self.cipher_suites.encode(out);
        try self.legacy_compression_methods.encode(out);
        try self.extensions.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        const protover = try in.consume(u16);
        if (protover != legacy_version)
            return error.UnsupportedTLSVersion;

        const rand = blk: {
            const r = try in.consumeBytes(32);
            const arr: [32]u8 = undefined;
            mem.copy(u8, &arr, r);
            break :blk arr;
        };
        const legacy_session_id = try LegacySessionId.decode(allocator, in);
        errdefer legacy_session_id.deinit();
        const cipher_suites = try CipherSuites.decode(allocator, in);
        errdefer cipher_suites.deinit();
        const legacy_compression_methods = try LegacyCompressionMethods.decode(allocator, in);
        errdefer legacy_compression_methods.deinit();
        const extensions = try Extensions.decode(allocator, in);
        errdefer extensions.deinit();

        return .{
            .random = rand,
            .legacy_session_id = legacy_session_id,
            .cipher_suites = cipher_suites,
            .legacy_compression_methods = legacy_compression_methods,
            .extensions = extensions,
        };
    }

    pub fn deinit(self: Self) void {
        self.legacy_session_id.deinit();
        self.cipher_suites.deinit();
        self.legacy_compression_methods.deinit();
        self.extensions.deinit();
    }
};

test "ClientHello decode" {
    // Brought from https://www.rfc-editor.org/rfc/rfc8448#section-3
    var buf = [_]u8{
        0x03, 0x03, 0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81,
        0x63, 0xba, 0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19,
        0x6a, 0x6d, 0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12,
        0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d,
        0xec, 0xe7, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13,
        0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91, 0x00,
        0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06,
        0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00,
        0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
        0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01,
        0x03, 0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00,
        0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00,
        0x20, 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd,
        0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba,
        0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae,
        0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf,
        0x2c, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03,
        0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04,
        0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
        0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02,
        0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02,
        0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01,
    };

    var in = Bytes{ .buf = &buf };
    const got = try ClientHello.decode(std.testing.allocator, &in);
    try std.testing.expectEqual(ClientHello.legacy_version, got.legacy_version);
}
