const std = @import("std");
const utils = @import("../utils.zig");
const Bytes = @import("../bytes.zig").Bytes;

const SupportedCipherSuites = std.EnumSet(CipherSuite).init(.{ .TLS_AES_128_GCM_SHA256 = true });

/// Pick up a cipher suite that we currently support, if any, from the given set of cipher suites.
/// When there are multiple cipher suites included in the set, one that appears first in the set will be chosen.
/// If there's no supported cipher suite this returns `null`.
pub fn pickCipherSuite(cipher_suites: []const CipherSuite) ?CipherSuite {
    for (cipher_suites) |c| {
        if (SupportedCipherSuites.contains(c))
            return c;
    }
    return null;
}

test "pickCipherSuite" {
    try std.testing.expect(pickCipherSuite(&.{}) == null);
    try std.testing.expect(pickCipherSuite(&.{.TLS_CHACHA20_POLY1305_SHA256}) == null);
    try std.testing.expect(pickCipherSuite(&.{ .TLS_CHACHA20_POLY1305_SHA256, .TLS_AES_256_GCM_SHA384 }) == null);

    try std.testing.expectEqual(
        CipherSuite.TLS_AES_128_GCM_SHA256,
        pickCipherSuite(&.{.TLS_AES_128_GCM_SHA256}).?,
    );
    try std.testing.expectEqual(
        CipherSuite.TLS_AES_128_GCM_SHA256,
        pickCipherSuite(&.{ .TLS_CHACHA20_POLY1305_SHA256, .TLS_AES_128_GCM_SHA256 }).?,
    );
}

/// https://datatracker.ietf.org/doc/html/rfc9001#section-5.3
///
/// > QUIC can use any of the cipher suites defined in [TLS13] with the
/// > exception of TLS_AES_128_CCM_8_SHA256.
///
/// https://www.rfc-editor.org/rfc/rfc8446.html#appendix-B.4
///
/// > This specification defines the following cipher suites for use with TLS 1.3.
///
///           +------------------------------+-------------+
///           | Description                  | Value       |
///           +------------------------------+-------------+
///           | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
///           |                              |             |
///           | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
///           |                              |             |
///           | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
///           |                              |             |
///           | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
///           |                              |             |
///           | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
///           +------------------------------+-------------+
pub const CipherSuite = enum {
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_AES_128_CCM_SHA256,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        _ = self;
        return 2 * utils.sizeOf(u8);
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        const value: [2]u8 = switch (self) {
            .TLS_AES_128_GCM_SHA256 => .{ 0x13, 0x01 },
            .TLS_AES_256_GCM_SHA384 => .{ 0x13, 0x02 },
            .TLS_CHACHA20_POLY1305_SHA256 => .{ 0x13, 0x03 },
            .TLS_AES_128_CCM_SHA256 => .{ 0x13, 0x04 },
        };
        try out.putBytes(&value);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        _ = allocator;

        const value = try in.consumeBytes(2);
        if (value[0] != 0x13)
            return error.UnsupportedCipherSuite;

        return switch (value[1]) {
            0x01 => .TLS_AES_128_GCM_SHA256,
            0x02 => .TLS_AES_256_GCM_SHA384,
            0x03 => .TLS_CHACHA20_POLY1305_SHA256,
            0x04 => .TLS_AES_128_CCM_SHA256,
            else => error.UnsupportedCipherSuite,
        };
    }

    pub fn deinit(self: Self) void {
        // no-op
        _ = self;
    }
};

test "encode CipherSuite" {
    const suite = CipherSuite.TLS_CHACHA20_POLY1305_SHA256;
    defer suite.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try suite.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x13, 0x03 }, out.split().former.buf);
}

test "decode CipherSuite" {
    var buf = [_]u8{ 0x13, 0x03 };
    var in = Bytes{ .buf = &buf };

    const got = try CipherSuite.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, got);
}
