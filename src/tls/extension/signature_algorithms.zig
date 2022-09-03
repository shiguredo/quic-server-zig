const std = @import("std");
const meta = std.meta;
const VariableLengthVector = @import("../../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../../bytes.zig").Bytes;
const utils = @import("../../utils.zig");

pub const SupportedSignatureAlgorithms = VariableLengthVector(SignatureScheme, 65534);

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
///
/// struct {
///     SignatureScheme supported_signature_algorithms<2..2^16-2>;
/// } SignatureSchemeList;
pub const SignatureSchemeList = struct {
    supported_signature_algorithms: SupportedSignatureAlgorithms,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.supported_signature_algorithms.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.supported_signature_algorithms.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        return Self{
            .supported_signature_algorithms = try SupportedSignatureAlgorithms.decode(allocator, in),
        };
    }

    pub fn deinit(self: Self) void {
        self.supported_signature_algorithms.deinit();
    }
};

test "encode SignatureSchemeList" {
    const sig_list = SignatureSchemeList{
        .supported_signature_algorithms = try SupportedSignatureAlgorithms.fromSlice(
            std.testing.allocator,
            &.{ .rsa_pkcs1_sha256, .ed25519 },
        ),
    };
    defer sig_list.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try sig_list.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x04, 0x04, 0x01, 0x08, 0x07 }, out.split().former.buf);
}

test "decode SignatureSchemeList" {
    var buf = [_]u8{ 0x00, 0x04, 0x04, 0x01, 0x08, 0x07 };
    var in = Bytes{ .buf = &buf };

    const got = try SignatureSchemeList.decode(std.testing.allocator, &in);
    defer got.deinit();

    const algos = got.supported_signature_algorithms.data.items;
    try std.testing.expectEqual(@as(usize, 2), algos.len);
    try std.testing.expectEqual(SignatureScheme.rsa_pkcs1_sha256, algos[0]);
    try std.testing.expectEqual(SignatureScheme.ed25519, algos[1]);
}

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
///
/// enum {
///     /* RSASSA-PKCS1-v1_5 algorithms */
///     rsa_pkcs1_sha256(0x0401),
///     rsa_pkcs1_sha384(0x0501),
///     rsa_pkcs1_sha512(0x0601),
///
///     /* ECDSA algorithms */
///     ecdsa_secp256r1_sha256(0x0403),
///     ecdsa_secp384r1_sha384(0x0503),
///     ecdsa_secp521r1_sha512(0x0603),
///
///     /* RSASSA-PSS algorithms with public key OID rsaEncryption */
///     rsa_pss_rsae_sha256(0x0804),
///     rsa_pss_rsae_sha384(0x0805),
///     rsa_pss_rsae_sha512(0x0806),
///
///     /* EdDSA algorithms */
///     ed25519(0x0807),
///     ed448(0x0808),
///
///     /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
///     rsa_pss_pss_sha256(0x0809),
///     rsa_pss_pss_sha384(0x080a),
///     rsa_pss_pss_sha512(0x080b),
///
///     /* Legacy algorithms */
///     rsa_pkcs1_sha1(0x0201),
///     ecdsa_sha1(0x0203),
///
///     /* Reserved Code Points */
///     private_use(0xFE00..0xFFFF),
///     (0xFFFF)
/// } SignatureScheme;
///
/// > Note: This enum is named "SignatureScheme" because there is already a
/// > "SignatureAlgorithm" type in TLS 1.2
pub const SignatureScheme = enum(u16) {
    // RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    // ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    // RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    // EdDSA algorithms */
    ed25519 = 0x0807,
    ed448 = 0x0808,

    // RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    // Legacy algorithms
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,

    // Reserved Code Points
    // private_use(0xFE00..0xFFFF),

    const Self = @This();
    const TagType = @typeInfo(Self).Enum.tag_type;

    pub fn encodedLength(self: Self) usize {
        _ = self;
        return utils.sizeOf(TagType);
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.put(TagType, @enumToInt(self));
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        _ = allocator;
        const val = try in.consume(TagType);
        return meta.intToEnum(Self, val);
    }

    pub fn deinit(self: Self) void {
        // no-op
        _ = self;
    }
};

test "encode SignatureScheme" {
    const rsa_pkcs1_sha256 = SignatureScheme.rsa_pkcs1_sha256;
    defer rsa_pkcs1_sha256.deinit();
    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try rsa_pkcs1_sha256.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x04, 0x01 }, out.split().former.buf);
}

test "decode SignatureScheme" {
    var buf = [_]u8{ 0x04, 0x01 };
    var in = Bytes{ .buf = &buf };

    const got = try SignatureScheme.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(SignatureScheme.rsa_pkcs1_sha256, got);
}
