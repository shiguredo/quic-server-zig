const std = @import("std");
const mem = std.mem;
const io = std.io;
const Allocator = mem.Allocator;
const crypto = std.crypto;
const ecdsa = std.crypto.sign.ecdsa;
const Sha256 = crypto.hash.sha2.Sha256;
const assert = std.debug.assert;
const VariableLengthVector = @import("../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../bytes.zig").Bytes;
const SignatureScheme = @import("./extension/signature_algorithms.zig").SignatureScheme;
const ECPrivateKey = @import("./ec_private_key.zig");

/// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3
///
/// struct {
///     SignatureScheme algorithm;
///     opaque signature<0..2^16-1>;
/// } CertificateVerify;
pub const CertificateVerify = struct {
    algorithm: SignatureScheme,
    signature: Signature,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.algorithm.encodedLength() + self.signature.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.algorithm.encode(out);
        try self.signature.encode(out);
    }

    pub fn decode(allocator: Allocator, in: *Bytes) !Self {
        const algo = try SignatureScheme.decode(allocator, in);
        errdefer algo.deinit();
        const sig = try Signature.decode(allocator, in);
        errdefer sig.deinit();

        return Self{
            .algorithm = algo,
            .signature = sig,
        };
    }

    pub fn deinit(self: Self) void {
        self.algorithm.deinit();
        self.signature.deinit();
    }

    pub fn sign(
        allocator: Allocator,
        algo: SignatureScheme,
        secret_key_der: []const u8,
        transcript_hash_input: []const u8,
        is_server: bool,
    ) !Self {
        const transcript_hash = switch (algo) {
            .ecdsa_secp256r1_sha256 => hash: {
                const Hash = Sha256;
                var ret: [Hash.digest_length]u8 = undefined;
                Hash.hash(transcript_hash_input, &ret, .{});
                break :hash ret;
            },
            // We support ecdsa_secp256r1_sha256 only right now.
            else => unreachable,
        };

        var content: [1024]u8 = undefined;
        const content_len = try contentToBeSigned(&transcript_hash, is_server, &content);
        const msg = content[0..content_len];

        const signed = switch (algo) {
            .ecdsa_secp256r1_sha256 => s: {
                const EcdsaP256Sha256 = ecdsa.EcdsaP256Sha256;
                const SecretKey = EcdsaP256Sha256.SecretKey;

                const ec_key = try ECPrivateKey.parseDer(allocator, secret_key_der);
                defer ec_key.deinit();

                const secret_key = ec_key.private_key;

                assert(secret_key.len == SecretKey.encoded_length);
                var sec: [SecretKey.encoded_length]u8 = undefined;
                mem.copy(u8, &sec, secret_key);

                const seckey = try SecretKey.fromBytes(sec);
                const key_pair = try EcdsaP256Sha256.KeyPair.fromSecretKey(seckey);

                const s = try key_pair.sign(msg, null);

                var sig_der: [EcdsaP256Sha256.Signature.der_encoded_max_length]u8 = undefined;
                break :s s.toDer(&sig_der);
            },
            // We support ecdsa_secp256r1_sha256 only right now.
            else => unreachable,
        };

        return Self{
            .algorithm = algo,
            .signature = try Signature.fromSlice(allocator, signed),
        };
    }
};

pub const Signature = VariableLengthVector(u8, 65535);

test "encode CertificateVerify" {
    const cv = CertificateVerify{
        .algorithm = .rsa_pkcs1_sha256,
        .signature = try Signature.fromSlice(std.testing.allocator, &.{ 0x01, 0x02, 0x03 }),
    };
    defer cv.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try cv.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x04, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03 }, out.split().former.buf);
}

test "decode CertificateVerify" {
    var buf = [_]u8{
        0x04, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03,
    };

    var in = Bytes{ .buf = &buf };
    const got = try CertificateVerify.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expect(got.algorithm == .rsa_pkcs1_sha256);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, got.signature.data.items);
}

/// Generate the content that is then signed. The result will be written to `out`,
/// and the number of bytes written is returned.
/// If the length of `out` is not enough, `error.BufferTooShort` is returned.
fn contentToBeSigned(transcript_hash: []const u8, is_server: bool, out: []u8) !usize {
    const octets = [_]u8{0x20} ** 64;
    const ctx_str = if (is_server)
        "TLS 1.3, server CertificateVerify"
    else
        "TLS 1.3, client CertificateVerify";
    const sep = [_]u8{0x00};

    var buf = Bytes{ .buf = out };

    try buf.putBytes(&octets);
    try buf.putBytes(ctx_str);
    try buf.putBytes(&sep);
    try buf.putBytes(transcript_hash);

    return buf.pos;
}

test "contentToBeSigned RFC 8446" {
    const transcript_hash = [_]u8{0x01} ** 32;
    var out: [1024]u8 = undefined;

    const written = try contentToBeSigned(&transcript_hash, true, &out);

    try std.testing.expectEqualSlices(u8, &.{
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33, 0x2c,
        0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
        0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
        0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66,
        0x79, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01,
    }, out[0..written]);
}
