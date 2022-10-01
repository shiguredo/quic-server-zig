const std = @import("std");
const math = std.math;
const Allocator = std.mem.Allocator;
const VariableLengthVector = @import("../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../bytes.zig").Bytes;
const Extension = @import("./extension.zig").Extension;

/// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2
///
/// enum {
///     X509(0),
///     RawPublicKey(2),
///     (255)
/// } CertificateType;
///
/// struct {
///     select (certificate_type) {
///         case RawPublicKey:
///           /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
///           opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
///
///         case X509:
///           opaque cert_data<1..2^24-1>;
///     };
///     Extension extensions<0..2^16-1>;
/// } CertificateEntry;
///
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
pub const Certificate = struct {
    certificate_request_context: CertificateRequestContext,
    certificate_list: CertificateList,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.certificate_request_context.encodedLength() + self.certificate_list.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.certificate_request_context.encode(out);
        try self.certificate_list.encode(out);
    }

    pub fn decode(allocator: Allocator, in: *Bytes) !Self {
        const ctx = try CertificateRequestContext.decode(allocator, in);
        errdefer ctx.deinit();
        const certlist = try CertificateList.decode(allocator, in);
        errdefer ctx.deinit();

        return Self{
            .certificate_request_context = ctx,
            .certificate_list = certlist,
        };
    }

    // TODO(magurotuna): support certificate chain
    pub fn fromCert(allocator: Allocator, cert: []const u8) !Self {
        const ctx = try CertificateRequestContext.fromSlice(allocator, &.{});
        errdefer ctx.deinit();
        const list = try CertificateList.fromSlice(allocator, &.{
            .{
                .cert_data = try CertData.fromSlice(allocator, cert),
                .extensions = try Extensions.fromSlice(allocator, &.{}),
            },
        });
        errdefer list.deinit();

        return Self{
            .certificate_request_context = ctx,
            .certificate_list = list,
        };
    }

    pub fn deinit(self: Self) void {
        self.certificate_request_context.deinit();
        self.certificate_list.deinit();
    }
};

test "encode Certificate" {
    const c = Certificate{
        .certificate_request_context = try CertificateRequestContext.fromSlice(std.testing.allocator, &.{}),
        .certificate_list = try CertificateList.fromSlice(std.testing.allocator, &.{
            .{
                .cert_data = try CertData.fromSlice(std.testing.allocator, &.{ 0x01, 0x02, 0x03 }),
                .extensions = try Extensions.fromSlice(std.testing.allocator, &.{}),
            },
        }),
    };
    defer c.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try c.encode(&out);

    // zig fmt: off
    try std.testing.expectEqualSlices(u8, &.{ 
        // certificate_request_context length
        0x00, 
        // certificate_list length
        0x00, 0x00, 0x08,
        0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00,
    }, out.split().former.buf);
    // zig fmt: on
}

test "decode Certificate" {
    var buf = [_]u8{
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x03, 0x01,
        0x02, 0x03, 0x00, 0x00,
    };
    var in = Bytes{ .buf = &buf };
    const got = try Certificate.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(usize, 0), got.certificate_request_context.data.items.len);
    try std.testing.expectEqual(@as(usize, 1), got.certificate_list.data.items.len);
    const cert = got.certificate_list.data.items[0];
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, cert.cert_data.data.items);
    try std.testing.expectEqual(@as(usize, 0), cert.extensions.data.items.len);
}

pub const CertificateRequestContext = VariableLengthVector(u8, 255);
pub const CertificateList = VariableLengthVector(CertificateEntry, math.pow(usize, 2, 24) - 1);
pub const Extensions = VariableLengthVector(Extension(.server), 65535);
pub const CertData = VariableLengthVector(u8, math.pow(usize, 2, 24) - 1);

/// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2
///
/// enum {
///     X509(0),
///     RawPublicKey(2),
///     (255)
/// } CertificateType;
///
/// struct {
///     select (certificate_type) {
///         case RawPublicKey:
///           /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
///           opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
///
///         case X509:
///           opaque cert_data<1..2^24-1>;
///     };
///     Extension extensions<0..2^16-1>;
/// } CertificateEntry;
///
/// Currently we assume that certificate_type is always X509.
pub const CertificateEntry = struct {
    cert_data: CertData,
    extensions: Extensions,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.cert_data.encodedLength() + self.extensions.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.cert_data.encode(out);
        try self.extensions.encode(out);
    }

    pub fn decode(allocator: Allocator, in: *Bytes) !Self {
        const data = try CertData.decode(allocator, in);
        errdefer data.deinit();
        const exts = try Extensions.decode(allocator, in);
        errdefer exts.deinit();

        return Self{
            .cert_data = data,
            .extensions = exts,
        };
    }

    pub fn deinit(self: Self) void {
        self.cert_data.deinit();
        self.extensions.deinit();
    }
};

test "encode CertificateEntry" {
    const ce = CertificateEntry{
        .cert_data = try CertData.fromSlice(std.testing.allocator, &.{ 0x01, 0x02, 0x03 }),
        .extensions = try Extensions.fromSlice(std.testing.allocator, &.{}),
    };
    defer ce.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ce.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00 }, out.split().former.buf);
}

test "decode CertificateEntry" {
    var buf = [_]u8{ 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00 };
    var in = Bytes{ .buf = &buf };
    const got = try CertificateEntry.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, got.cert_data.data.items);
    try std.testing.expectEqual(@as(usize, 0), got.extensions.data.items.len);
}
