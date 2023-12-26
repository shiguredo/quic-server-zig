const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;
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
    if (CipherSuite.Aead != Aes128Gcm or
        CipherSuite.Hkdf != HkdfSha256 or
        CipherSuite.Hmac != HmacSha256)
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

/// Get the early secret from an optional pre-shared key.
/// https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1
pub fn earlySecret(comptime CipherSuite: type, pre_shared_key: ?[]const u8) [CipherSuite.Hmac.mac_length]u8 {
    const salt = [_]u8{};
    // > If a given secret is not available, then the 0-value consisting of a
    // > string of Hash.length bytes set to zeros is used.  Note that this
    // > does not mean skipping rounds, so if PSK is not in use, Early Secret
    // > will still be HKDF-Extract(0, 0).
    const default_ikm = [_]u8{0x00} ** CipherSuite.Hmac.mac_length;
    const ikm = pre_shared_key orelse &default_ikm;
    return CipherSuite.Hkdf.extract(&salt, ikm);
}

/// Caculate "Handshake Secret" as described in RFC 8446:
///
/// https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1
///
///           0
///           |
///           v
/// PSK ->  HKDF-Extract = Early Secret
///           |
///           +-----> Derive-Secret(., "ext binder" | "res binder", "")
///           |                     = binder_key
///           |
///           +-----> Derive-Secret(., "c e traffic", ClientHello)
///           |                     = client_early_traffic_secret
///           |
///           +-----> Derive-Secret(., "e exp master", ClientHello)
///           |                     = early_exporter_master_secret
///           v
///     Derive-Secret(., "derived", "")
///           |
///           v
/// (EC)DHE -> HKDF-Extract = Handshake Secret
pub fn handshakeSecret(
    comptime CipherSuite: type,
    early_secret: []const u8,
    shared_secret: []const u8,
) ![CipherSuite.Hmac.mac_length]u8 {
    if (early_secret.len != CipherSuite.Hmac.mac_length)
        return error.InvalidSecretLength;

    const derived_secret = ds: {
        var s: [CipherSuite.Hmac.mac_length]u8 = undefined;
        mem.copy(u8, &s, early_secret);
        break :ds try deriveSecret(CipherSuite, s, "derived", "");
    };

    return CipherSuite.Hkdf.extract(&derived_secret, shared_secret);
}

/// Caculate "Handshake Traffic Secret" as described in RFC 8446:
///
/// https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1
///
/// (EC)DHE -> HKDF-Extract = Handshake Secret
///           |
///           +-----> Derive-Secret(., "c hs traffic",
///           |                     ClientHello...ServerHello)
///           |                     = client_handshake_traffic_secret
///           |
///           +-----> Derive-Secret(., "s hs traffic",
///           |                     ClientHello...ServerHello)
///           |                     = server_handshake_traffic_secret
pub fn handshakeTrafficSecret(
    comptime CipherSuite: type,
    handshake_secret: [CipherSuite.Hmac.mac_length]u8,
    ch_sh_msg: []const u8,
    is_server: bool,
) ![CipherSuite.Hmac.mac_length]u8 {
    const label = if (is_server) "s hs traffic" else "c hs traffic";

    return try deriveSecret(CipherSuite, handshake_secret, label, ch_sh_msg);
}

pub fn verifyDataForFinished(
    comptime CipherSuite: type,
    base_key: [CipherSuite.Hmac.mac_length]u8,
    transcript_hash_key: []const u8,
) ![CipherSuite.Hmac.mac_length]u8 {
    var finished_key: [CipherSuite.Hash.digest_length]u8 = undefined;
    try hkdfExpandLabel(CipherSuite, base_key, "finished", "", &finished_key);

    var transcript_hash: [CipherSuite.Hash.digest_length]u8 = undefined;
    CipherSuite.Hash.hash(transcript_hash_key, &transcript_hash, .{});

    var out: [CipherSuite.Hmac.mac_length]u8 = undefined;
    CipherSuite.Hmac.create(&out, &transcript_hash, &finished_key);
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

    const hkdfLabel = try HkdfLabel.new(allocator, @as(u16, @intCast(out.len)), label, ctx);

    // TODO(magurotuna): consider more appropriate array size
    var encoded_label: [4096]u8 = undefined;
    var bs = Bytes{ .buf = &encoded_label };
    try hkdfLabel.encode(&bs);

    CipherSuite.Hkdf.expand(out, bs.split().former.buf, secret);
}

/// `Derive-Secret` function which is defined in RFC 8446:
///
/// https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1
///
/// > Derive-Secret(Secret, Label, Messages) =
/// >  HKDF-Expand-Label(Secret, Label,
/// >                    Transcript-Hash(Messages), Hash.length)
fn deriveSecret(
    comptime CipherSuite: type,
    secret: [CipherSuite.Hmac.mac_length]u8,
    label: []const u8,
    messages: []const u8,
) ![CipherSuite.Hmac.mac_length]u8 {
    var transcript_hash: [CipherSuite.Hash.digest_length]u8 = undefined;
    CipherSuite.Hash.hash(messages, &transcript_hash, .{});
    var out: [CipherSuite.Hmac.mac_length]u8 = undefined;
    try hkdfExpandLabel(CipherSuite, secret, label, &transcript_hash, &out);
    return out;
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
    _ = TlsSecretTest;
    _ = DeriveTest;
}

// Based on RFC 8448:
// https://www.rfc-editor.org/rfc/rfc8448.html#section-3
const TlsSecretTest = struct {
    const MOCK_TLS_AES_128_GCM_SHA256 = struct {
        const Aead = Aes128Gcm;
        const Hmac = HmacSha256;
        const Hkdf = HkdfSha256;
        const Hash = Sha256;
    };

    test "Early Secret without pre-shared key" {
        const got = earlySecret(MOCK_TLS_AES_128_GCM_SHA256, null);
        try std.testing.expectEqualSlices(u8, &.{
            0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
            0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
            0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
            0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a,
        }, &got);
    }

    test "Handshake Secret" {
        const early_secret = [_]u8{
            0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
            0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
            0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
            0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a,
        };

        const local_private = [_]u8{
            0xb1, 0x58, 0x0e, 0xea, 0xdf, 0x6d, 0xd5, 0x89,
            0xb8, 0xef, 0x4f, 0x2d, 0x56, 0x52, 0x57, 0x8c,
            0xc8, 0x10, 0xe9, 0x98, 0x01, 0x91, 0xec, 0x8d,
            0x05, 0x83, 0x08, 0xce, 0xa2, 0x16, 0xa2, 0x1e,
        };
        const remote_public = [_]u8{
            0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43,
            0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe,
            0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d,
            0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c,
        };
        const shared_secret = try crypto.dh.X25519.scalarmult(local_private, remote_public);
        try std.testing.expectEqualSlices(u8, &.{
            0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63,
            0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b, 0x9f, 0x0d,
            0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef,
            0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d,
        }, &shared_secret);

        const got = try handshakeSecret(MOCK_TLS_AES_128_GCM_SHA256, &early_secret, &shared_secret);

        try std.testing.expectEqualSlices(u8, &.{
            0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f,
            0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01,
            0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2,
            0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac,
        }, &got);
    }

    test "client_handshake_traffic_secret and server_handshake_traffic_secret" {
        const handshake_secret = [_]u8{
            0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f,
            0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01,
            0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2,
            0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac,
        };
        const ch_msg = [_]u8{
            0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34,
            0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38,
            0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff, 0xa2,
            0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, 0xa2, 0xef,
            0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, 0x00, 0x00,
            0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01,
            0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x0b, 0x00,
            0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76,
            0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00,
            0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01,
            0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00,
            0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00,
            0x24, 0x00, 0x1d, 0x00, 0x20, 0x99, 0x38, 0x1d,
            0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e,
            0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e,
            0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69,
            0x1e, 0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00,
            0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20,
            0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
            0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
            0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01,
            0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02,
            0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c,
            0x00, 0x02, 0x40, 0x01,
        };
        const sh_msg = [_]u8{
            0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf,
            0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e,
            0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93, 0x0c,
            0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda, 0xc1, 0x55,
            0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28, 0x00, 0x13,
            0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24,
            0x00, 0x1d, 0x00, 0x20, 0xc9, 0x82, 0x88, 0x76,
            0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb,
            0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25,
            0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0,
            0x4e, 0x75, 0x1f, 0x0f, 0x00, 0x2b, 0x00, 0x02,
            0x03, 0x04,
        };
        const ch_sh_msg = ch_msg ++ sh_msg;

        const client_handshake_traffic_secret = try handshakeTrafficSecret(MOCK_TLS_AES_128_GCM_SHA256, handshake_secret, &ch_sh_msg, false);
        try std.testing.expectEqualSlices(u8, &.{
            0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35,
            0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e, 0x2d, 0x8f,
            0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96,
            0x00, 0x74, 0x6a, 0x0e, 0x27, 0xa5, 0x5a, 0x21,
        }, &client_handshake_traffic_secret);

        const server_handshake_traffic_secret = try handshakeTrafficSecret(MOCK_TLS_AES_128_GCM_SHA256, handshake_secret, &ch_sh_msg, true);
        try std.testing.expectEqualSlices(u8, &.{
            0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e,
            0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
            0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d,
            0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38,
        }, &server_handshake_traffic_secret);
    }
};

// Based on RFC 9001:
// https://www.rfc-editor.org/rfc/rfc9001.html#name-keys
const DeriveTest = struct {
    const MOCK_TLS_AES_128_GCM_SHA256 = struct {
        const Aead = Aes128Gcm;
        const Hmac = HmacSha256;
        const Hkdf = HkdfSha256;
        const Hash = Sha256;
    };
    const client_dcid = [_]u8{
        0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
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

    test "Client Initial Secret for TLS_AES_128_GCM_SHA256" {
        const got = try initialSecret(MOCK_TLS_AES_128_GCM_SHA256, &client_dcid, false);
        try std.testing.expectEqualSlices(u8, &client_initial_secret, &got);
    }

    test "Server Initial Secret for TLS_AES_128_GCM_SHA256" {
        const got = try initialSecret(MOCK_TLS_AES_128_GCM_SHA256, &client_dcid, true);
        try std.testing.expectEqualSlices(u8, &server_initial_secret, &got);
    }

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
