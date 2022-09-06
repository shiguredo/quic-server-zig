const std = @import("std");
const VariableLengthVector = @import("../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../bytes.zig").Bytes;
const CipherSuite = @import("./cipher_suite.zig").CipherSuite;
const Extension = @import("./extension.zig").Extension;
const utils = @import("../utils.zig");

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3
///
/// uint16 ProtocolVersion;
/// opaque Random[32];
///
/// uint8 CipherSuite[2];    /* Cryptographic suite selector */
///
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id_echo<0..32>;
///     CipherSuite cipher_suite;
///     uint8 legacy_compression_method = 0;
///     Extension extensions<6..2^16-1>;
/// } ServerHello;
pub const ServerHello = struct {
    pub const ProtocolVersion = u16;
    pub const Random = [32]u8;
    pub const LegacySessionId = VariableLengthVector(u8, 32);
    pub const LegacyCompressionMethod = u8;
    pub const Extensions = VariableLengthVector(Extension(.server), 65535);

    const legacy_version: ProtocolVersion = 0x0303;
    const legacy_compression_method: LegacyCompressionMethod = 0;

    legacy_version: u16 = legacy_version,
    random: Random,
    legacy_session_id_echo: LegacySessionId,
    cipher_suite: CipherSuite,
    legacy_compression_method: LegacyCompressionMethod = legacy_compression_method,
    extensions: Extensions,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        var len: usize = 0;
        len += utils.sizeOf(ProtocolVersion);
        len += utils.sizeOf(Random);
        len += self.legacy_session_id_echo.encodedLength();
        len += self.cipher_suite.encodedLength();
        len += utils.sizeOf(@TypeOf(self.legacy_compression_method));
        len += self.extensions.encodedLength();
        return len;
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.put(ProtocolVersion, self.legacy_version);
        try out.putBytes(&self.random);
        try self.legacy_session_id_echo.encode(out);
        try self.cipher_suite.encode(out);
        try out.put(LegacyCompressionMethod, self.legacy_compression_method);
        try self.extensions.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        // TODO(magurotuna): implement
        _ = allocator;
        _ = in;
        return error.Unimplemented;
    }

    pub fn deinit(self: Self) void {
        self.legacy_session_id_echo.deinit();
        self.extensions.deinit();
    }
};

test "encode Server Hello" {
    const sh = ServerHello{
        .random = .{0x42} ** 32,
        .legacy_session_id_echo = try ServerHello.LegacySessionId.fromSlice(std.testing.allocator, &.{0x01}),
        .cipher_suite = .TLS_AES_128_GCM_SHA256,
        .extensions = try ServerHello.Extensions.fromSlice(std.testing.allocator, &.{}),
    };
    defer sh.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try sh.encode(&out);

    // zig fmt: off
    try std.testing.expectEqualSlices(u8, &.{
        0x03, 0x03,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x01, 0x01,
        0x13, 0x01,
        0x00,
        0x00, 0x00,
    }, out.split().former.buf);
    // zig fmt: on
}

test "encode Server Hello with extensions" {
    const KeyExchange = @import("../tls/extension/key_share.zig").KeyExchange;

    const sh = ServerHello{
        .random = .{
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
            0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        },
        .legacy_session_id_echo = try ServerHello.LegacySessionId.fromSlice(std.testing.allocator, &.{0}),
        .cipher_suite = .TLS_AES_128_GCM_SHA256,
        .extensions = try ServerHello.Extensions.fromSlice(std.testing.allocator, &.{
            .{
                .key_share = .{
                    .server_share = .{
                        .group = .x25519,
                        .key_exchange = try KeyExchange.fromSlice(std.testing.allocator, &.{
                            0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d,
                            0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10,
                            0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa,
                            0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15,
                        }),
                    },
                },
            },
            .{
                .supported_versions = .{
                    .selected_version = 0x03_04,
                },
            },
        }),
    };
    defer sh.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try sh.encode(&out);

    // zig fmt: off
    try std.testing.expectEqualSlices(u8, &.{
        0x03, 0x03,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x01, 0x00,
        0x13, 0x01,
        0x00,

        // extension length
        0x00, 0x2e,

        // key_share extension
        0x00, 0x33,
        0x00, 0x24,
        0x00, 0x1d,
        0x00, 0x20,
        0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d,
        0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10,
        0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa,
        0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15,

        // supported_versions extension
        0x00, 0x2b,
        0x00, 0x02,
        0x03, 0x04,
    }, out.split().former.buf);
    // zig fmt: on
}
