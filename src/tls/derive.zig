const std = @import("std");
const crypto = std.crypto;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const HmacSha384 = crypto.auth.hmac.sha2.HmacSha384;
const HkdfSha384 = crypto.kdf.hkdf.Hkdf(HmacSha384);
const Bytes = @import("../bytes.zig").Bytes;
const utils = @import("../utils.zig");
const VariableLengthVector = @import("../variable_length_vector.zig").VariableLengthVector;

pub fn initialSecret(
    comptime CipherSuite: type,
    client_dcid: []const u8,
    is_server: bool,
) ![CipherSuite.Hmac.mac_length]u8 {
    // https://www.rfc-editor.org/rfc/rfc9001#name-packet-protection
    //
    // > Initial packets use AEAD_AES_128_GCM with keys derived from the Destination Connection ID
    // > field of the first Initial packet sent by the client
    if (
        CipherSuite.Aead != Aes128Gcm or
        CipherSuite.Hkdf != HkdfSha256 or
        CipherSuite.Hmac != HmacSha256
    )
        @compileError("Initial packets must be protected with AEAD_AES_128_GCM");

    // https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
    const salt = [_]u8{
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
        0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
        0xcc, 0xbb, 0x7f, 0x0a,
    };
    const common_secret = HkdfSha256.extract(&salt, client_dcid);
    const label = if (is_server) "server in" else "client in";
    const ctx = "";
    var out: [CipherSuite.Hmac.mac_length]u8 = undefined;
    try hkdfExpandLabel(CipherSuite, common_secret, label, ctx, &out);
    return out;
}

/// Derive AEAD Key (key) from the given secret.
pub fn aeadKey(
    comptime CipherSuite: type,
    secret: [CipherSuite.Hmac.mac_length]u8,
) ![CipherSuite.Aead.key_length]u8 {
    const label = "quic key";
    const ctx = "";
    var out: [CipherSuite.Aead.key_length]u8 = undefined;
    try hkdfExpandLabel(CipherSuite, secret, label, ctx, &out);
    return out;
}

/// Derive Initialization Vector (IV) from the given secret.
///
/// https://www.rfc-editor.org/rfc/rfc9001.html#name-packet-protection-keys
///
/// > The Length provided with "quic iv" is the minimum length of the AEAD nonce
/// > or 8 bytes if that is larger
pub fn initializationVector(
    comptime CipherSuite: type,
    secret: [CipherSuite.Hmac.mac_length]u8,
) ![CipherSuite.Aead.nonce_length]u8 {
    const label = "quic iv";
    const ctx = "";
    var out: [CipherSuite.Aead.nonce_length]u8 = undefined;
    try hkdfExpandLabel(CipherSuite, secret, label, ctx, &out);
    return out;
}

/// Derives Header Protection Key (hp) from the given secret.
pub fn headerProtectionKey(
    comptime CipherSuite: type,
    secret: [CipherSuite.Hmac.mac_length]u8,
) ![CipherSuite.Aead.key_length]u8 {
    const label = "quic hp";
    const ctx = "";
    var out: [CipherSuite.Aead.key_length]u8 = undefined;
    try hkdfExpandLabel(CipherSuite, secret, label, ctx, &out);
    return out;
}

fn hkdfExpandLabel(
    comptime CipherSuite: type,
    secret: [CipherSuite.Hmac.mac_length]u8,
    label: []const u8,
    ctx: []const u8,
    out: []u8,
) !void {
    if (HkdfLabel.label_prefix.len + label.len > HkdfLabel.label_max_length) {
        return error.LabelTooLong;
    }
    if (ctx.len > HkdfLabel.ctx_max_length) {
        return error.ContextTooLong;
    }

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const hkdfLabel = try HkdfLabel.new(allocator, @intCast(u16, out.len), label, ctx);

    // TODO(magurotuna): consider more appropriate array size
    var encoded_label: [4096]u8 = undefined;
    var bs = Bytes{ .buf = &encoded_label };
    try hkdfLabel.encode(&bs);

    CipherSuite.Hkdf.expand(out, bs.split().former.buf, secret);
}

const HkdfLabel = struct {
    length: u16,
    label: Label,
    context: Context,

    const label_prefix = "tls13 ";
    const label_max_length = 255;
    const ctx_max_length = 255;

    const Self = @This();

    const Label = VariableLengthVector(u8, label_max_length);
    const Context = VariableLengthVector(u8, ctx_max_length);

    fn encodedLength(self: Self) usize {
        var len: usize = 0;
        for (@typeInfo(Self).Struct.fields) |field| {
            len += if (@typeInfo(field.field_type) == .Int)
                utils.sizeOf(field.field_type)
            else
                @field(self, field.name).encodedLength();
        }
        return len;
    }

    fn encode(self: Self, out: *Bytes) !void {
        try out.put(u16, self.length);
        try self.label.encode(out);
        try self.context.encode(out);
    }

    fn new(allocator: std.mem.Allocator, length: u16, label_data: []const u8, context_data: []const u8) !Self {
        const label = blk: {
            var lbl = try Label.fromSlice(allocator, label_prefix);
            errdefer lbl.deinit();
            try lbl.appendSlice(label_data);
            break :blk lbl;
        };
        errdefer label.deinit();

        const context = try Context.fromSlice(allocator, context_data);
        errdefer context.deinit();

        return Self{
            .length = length,
            .label = label,
            .context = context,
        };
    }

    fn deinit(self: Self) void {
        self.label.deinit();
        self.context.deinit();
    }
};

test {
    _ = DeriveTest;
}

// Based on RFC 9001:
// https://www.rfc-editor.org/rfc/rfc9001.html#name-keys
const DeriveTest = struct {
    const MOCK_TLS_AES_128_GCM_SHA256 = struct {
        const Aead = Aes128Gcm;
        const Hmac = HmacSha256;
        const Hkdf = HkdfSha256;
    };
    const client_initial_secret: [32]u8 = .{
        0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75,
        0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
        0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a,
        0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
    };
    const server_initial_secret: [32]u8 = .{
        0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd,
        0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
        0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d,
        0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b,
    };

    test "aeadKey for TLS_AES_128_GCM_SHA256" {
        {
            const got = try aeadKey(MOCK_TLS_AES_128_GCM_SHA256, client_initial_secret);

            try std.testing.expectEqualSlices(u8, &.{
                0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
                0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
            }, &got);
        }

        {
            const got = try aeadKey(MOCK_TLS_AES_128_GCM_SHA256, server_initial_secret);

            try std.testing.expectEqualSlices(u8, &.{
                0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c,
                0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37,
            }, &got);
        }
    }

    test "initializationVector for TLS_AES_128_GCM_SHA256" {
        {
            const got = try initializationVector(MOCK_TLS_AES_128_GCM_SHA256, client_initial_secret);

            try std.testing.expectEqualSlices(u8, &.{
                0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
                0x46, 0xfb, 0x25, 0x5c,
            }, &got);
        }

        {
            const got = try initializationVector(MOCK_TLS_AES_128_GCM_SHA256, server_initial_secret);

            try std.testing.expectEqualSlices(u8, &.{
                0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53,
                0xb0, 0xbb, 0xa0, 0x3e,
            }, &got);
        }
    }

    test "headerProtectionKey for TLS_AES_128_GCM_SHA256" {
        {
            const got = try headerProtectionKey(MOCK_TLS_AES_128_GCM_SHA256, client_initial_secret);

            try std.testing.expectEqualSlices(u8, &.{
                0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
                0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
            }, &got);
        }

        {
            const got = try headerProtectionKey(MOCK_TLS_AES_128_GCM_SHA256, server_initial_secret);

            try std.testing.expectEqualSlices(u8, &.{
                0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76,
                0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14,
            }, &got);
        }
    }
};
