const std = @import("std");
const VariableLengthVector = @import("../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../bytes.zig").Bytes;
const SignatureScheme = @import("./extension/signature_algorithms.zig").SignatureScheme;

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

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
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
