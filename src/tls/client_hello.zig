const std = @import("std");
const mem = std.mem;
const VariableLengthVector = @import("../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../bytes.zig").Bytes;
const CipherSuite = @import("./cipher_suite.zig").CipherSuite;
const Extension = @import("./extension.zig").Extension;
const ExtensionType = @import("./extension.zig").ExtensionType;
const utils = @import("../utils.zig");

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
    pub const ProtocolVersion = u16;
    pub const Random = [32]u8;
    pub const LegacySessionId = VariableLengthVector(u8, 32);
    pub const CipherSuites = VariableLengthVector(CipherSuite, 65534);
    pub const LegacyCompressionMethods = VariableLengthVector(u8, 255);
    pub const Extensions = VariableLengthVector(Extension(.client), 65535);

    const legacy_version: ProtocolVersion = 0x0303;

    legacy_version: u16 = legacy_version,
    random: Random,
    legacy_session_id: LegacySessionId,
    cipher_suites: CipherSuites,
    legacy_compression_methods: LegacyCompressionMethods,
    extensions: Extensions,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        var len: usize = 0;
        len += utils.sizeOf(ProtocolVersion);
        len += utils.sizeOf(Random);
        len += self.legacy_session_id.encodedLength();
        len += self.cipher_suites.encodedLength();
        len += self.legacy_compression_methods.encodedLength();
        len += self.extensions.encodedLength();
        return len;
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.put(ProtocolVersion, self.legacy_version);
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
            var arr: [32]u8 = undefined;
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

        return Self{
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
    const supported_groups = @import("./extension/supported_groups.zig");
    const supported_versions = @import("./extension/supported_versions.zig");
    const signature_algorithms = @import("./extension/signature_algorithms.zig");
    const psk_key_exchange_modes = @import("./extension/psk_key_exchange_modes.zig");

    // Brought from https://www.rfc-editor.org/rfc/rfc8448#section-3
    // zig fmt: off
    var buf = [_]u8{
        // legacy_version
        0x03, 0x03,

        // random
        0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba,
        0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d,
        0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18,
        0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7,

        // legacy_session_id
        0x00,

        // cipher_suites
        0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02,

        // legacy_compression_methods
        0x01, 0x00,

        // extensions
        0x00, 0x89,

        // server_name extension
        0x00, 0x00,
        0x00, 0x0b,
        0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76,
        0x65, 0x72,

        // renegotiation_info extension
        0xff, 0x01,
        0x00, 0x01,
        0x00,

        // supported_groups extension
        0x00, 0x0a,
        0x00, 0x14,
        0x00, 0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
        0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02,
        0x01, 0x03, 0x01, 0x04,

        // session_ticket extension
        0x00, 0x23,
        0x00, 0x00,

        // key_share extension
        0x00, 0x33,
        0x00, 0x26,
        0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x99, 0x38,
        0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d,
        0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0,
        0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13,
        0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c,

        // supported_versions extension
        0x00, 0x2b,
        0x00, 0x03,
        0x02, 0x03, 0x04,

        // signature_algorithms extension
        0x00, 0x0d,
        0x00, 0x18,
        0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
        0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
        0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01,
        // Next line is included in the test data shown in RFC 8448, but these are using DSA
        // as a signature algorithm, which RFC 8446 (TLS 1.3) deprecates. We ignore it here.
        //
        // https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
        //
        // > In particular, MD5 [SLOTH], SHA-224, and DSA MUST NOT be used.
        // 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02,

        // psk_key_exchange_modes extension
        0x00, 0x2d,
        0x00, 0x02,
        0x01, 0x01,

        // record_size_limit extension
        0x00, 0x1c,
        0x00, 0x02,
        0x40, 0x01,
    };
    // zig fmt: on

    var in = Bytes{ .buf = &buf };
    const got = try ClientHello.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual([32]u8{
        0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba,
        0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d,
        0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18,
        0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7,
    }, got.random);
    try std.testing.expectEqualSlices(u8, &[_]u8{}, got.legacy_session_id.data.items);
    try std.testing.expectEqualSlices(CipherSuite, &.{
        .TLS_AES_128_GCM_SHA256,
        .TLS_CHACHA20_POLY1305_SHA256,
        .TLS_AES_256_GCM_SHA384,
    }, got.cipher_suites.data.items);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, got.legacy_compression_methods.data.items);

    try std.testing.expectEqual(@as(usize, 9), got.extensions.data.items.len);

    const ext1 = got.extensions.data.items[0];
    try std.testing.expectEqual(ExtensionType.server_name, ext1);
    const server_name_list = ext1.server_name.server_name_list.data.items;
    try std.testing.expectEqual(@as(usize, 1), server_name_list.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 }, server_name_list[0].host_name.data.items);

    const ext2 = got.extensions.data.items[1];
    try std.testing.expectEqual(ExtensionType.renegotiation_info, ext2);
    try std.testing.expectEqualSlices(u8, &[_]u8{}, ext2.renegotiation_info.renegotiated_connection.data.items);

    const ext3 = got.extensions.data.items[2];
    try std.testing.expectEqual(ExtensionType.supported_groups, ext3);
    try std.testing.expectEqualSlices(supported_groups.NamedGroup, &.{
        .x25519, .secp256r1, .secp384r1, .secp521r1, .ffdhe2048, .ffdhe3072, .ffdhe4096, .ffdhe6144, .ffdhe8192,
    }, ext3.supported_groups.named_group_list.data.items);

    const ext4 = got.extensions.data.items[3];
    try std.testing.expectEqual(ExtensionType.session_ticket, ext4);
    try std.testing.expectEqualSlices(u8, &.{}, ext4.session_ticket.ticket.items);

    const ext5 = got.extensions.data.items[4];
    try std.testing.expectEqual(ExtensionType.key_share, ext5);
    const client_shares = ext5.key_share.client_shares.data.items;
    try std.testing.expectEqual(@as(usize, 1), client_shares.len);
    try std.testing.expectEqual(supported_groups.NamedGroup.x25519, client_shares[0].group);
    try std.testing.expectEqualSlices(u8, &.{
        0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43,
        0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe,
        0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d,
        0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c,
    }, client_shares[0].key_exchange.data.items);

    const ext6 = got.extensions.data.items[5];
    try std.testing.expectEqual(ExtensionType.supported_versions, ext6);
    try std.testing.expectEqualSlices(supported_versions.ProtocolVersion, &.{0x0304}, ext6.supported_versions.versions.data.items);

    const ext7 = got.extensions.data.items[6];
    try std.testing.expectEqual(ExtensionType.signature_algorithms, ext7);
    try std.testing.expectEqualSlices(signature_algorithms.SignatureScheme, &.{
        .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384, .ecdsa_secp521r1_sha512,
        .ecdsa_sha1,             .rsa_pss_rsae_sha256,    .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,    .rsa_pkcs1_sha256,       .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,       .rsa_pkcs1_sha1,
    }, ext7.signature_algorithms.supported_signature_algorithms.data.items);

    const ext8 = got.extensions.data.items[7];
    try std.testing.expectEqual(ExtensionType.psk_key_exchange_modes, ext8);
    try std.testing.expectEqualSlices(psk_key_exchange_modes.PskKeyExchangeMode, &.{.psk_dhe_ke}, ext8.psk_key_exchange_modes.ke_modes.data.items);

    const ext9 = got.extensions.data.items[8];
    try std.testing.expectEqual(ExtensionType.record_size_limit, ext9);
    try std.testing.expectEqual(@as(u16, 0x4001), ext9.record_size_limit.record_size_limit);
}
