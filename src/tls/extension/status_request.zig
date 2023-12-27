const std = @import("std");
const meta = std.meta;
const VariableLengthVector = @import("../../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../../bytes.zig").Bytes;
const utils = @import("../../utils.zig");

/// https://www.rfc-editor.org/rfc/rfc6066.html#section-8
///
/// struct {
///     CertificateStatusType status_type;
///     select (status_type) {
///         case ocsp: OCSPStatusRequest;
///     } request;
/// } CertificateStatusRequest;
pub const CertificateStatusRequest = union(CertificateStatusType) {
    ocsp: OCSPStatusRequest,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        var len: usize = 0;
        len += utils.sizeOf(CertificateStatusType.TagType);
        len += switch (self) {
            .ocsp => |o| o.encodedLength(),
        };
        return len;
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.put(CertificateStatusType.TagType, @intFromEnum(self));
        switch (self) {
            .ocsp => |o| try o.encode(out),
        }
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        const ty_num = try in.consume(CertificateStatusType.TagType);
        const status_type = try meta.intToEnum(CertificateStatusType, ty_num);

        return switch (status_type) {
            .ocsp => .{
                .ocsp = try OCSPStatusRequest.decode(allocator, in),
            },
        };
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            .ocsp => |o| o.deinit(),
        }
    }
};

test "encode CertificateStatusRequest" {
    const cert_req = CertificateStatusRequest{
        .ocsp = .{
            .responder_id_list = try OCSPStatusRequest.ResponderIDs.fromSlice(std.testing.allocator, &.{
                try OCSPStatusRequest.ResponderID.fromSlice(std.testing.allocator, &.{ 0x01, 0x02 }),
                try OCSPStatusRequest.ResponderID.fromSlice(std.testing.allocator, &.{ 0x03, 0x04, 0x05 }),
            }),
            .request_extensions = try OCSPStatusRequest.Extensions.fromSlice(std.testing.allocator, &.{0x06}),
        },
    };

    defer cert_req.deinit();
    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try cert_req.encode(&out);

    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0x00, 0x09, 0x00, 0x02, 0x01, 0x02, 0x00, 0x03, 0x03, 0x04, 0x05, 0x00, 0x01, 0x06 },
        out.split().former.buf,
    );
}

test "decode CertificateStatusRequest" {
    var buf = [_]u8{ 0x01, 0x00, 0x09, 0x00, 0x02, 0x01, 0x02, 0x00, 0x03, 0x03, 0x04, 0x05, 0x00, 0x01, 0x06 };
    var in = Bytes{ .buf = &buf };

    const got = try CertificateStatusRequest.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(CertificateStatusType.ocsp, got);

    const id_list = got.ocsp.responder_id_list.data.items;
    try std.testing.expectEqual(@as(usize, 2), id_list.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, id_list[0].data.items);
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0x04, 0x05 }, id_list[1].data.items);

    try std.testing.expectEqualSlices(u8, &.{0x06}, got.ocsp.request_extensions.data.items);
}

/// https://www.rfc-editor.org/rfc/rfc6066.html#section-8
///
/// enum { ocsp(1), (255) } CertificateStatusType;
pub const CertificateStatusType = enum(u8) {
    ocsp = 1,

    const Self = @This();
    const TagType = @typeInfo(Self).Enum.tag_type;
};

/// https://www.rfc-editor.org/rfc/rfc6066.html#section-8
///
/// struct {
///     ResponderID responder_id_list<0..2^16-1>;
///     Extensions  request_extensions;
/// } OCSPStatusRequest;
pub const OCSPStatusRequest = struct {
    responder_id_list: ResponderIDs,
    request_extensions: Extensions,

    pub const ResponderIDs = VariableLengthVector(ResponderID, 65535);
    pub const ResponderID = VariableLengthVector(u8, 65535);
    pub const Extensions = VariableLengthVector(u8, 65535);

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.responder_id_list.encodedLength() + self.request_extensions.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.responder_id_list.encode(out);
        try self.request_extensions.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        const id_list = try ResponderIDs.decode(allocator, in);
        errdefer id_list.deinit();
        const exts = try Extensions.decode(allocator, in);
        errdefer exts.deinit();

        return Self{
            .responder_id_list = id_list,
            .request_extensions = exts,
        };
    }

    pub fn deinit(self: Self) void {
        self.responder_id_list.deinit();
        self.request_extensions.deinit();
    }
};

test "encode OCSPStatusRequest" {
    const ocsp_req = OCSPStatusRequest{
        .responder_id_list = try OCSPStatusRequest.ResponderIDs.fromSlice(std.testing.allocator, &.{
            try OCSPStatusRequest.ResponderID.fromSlice(std.testing.allocator, &.{ 0x01, 0x02 }),
            try OCSPStatusRequest.ResponderID.fromSlice(std.testing.allocator, &.{ 0x03, 0x04, 0x05 }),
        }),
        .request_extensions = try OCSPStatusRequest.Extensions.fromSlice(std.testing.allocator, &.{0x06}),
    };
    defer ocsp_req.deinit();
    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ocsp_req.encode(&out);

    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x00, 0x09, 0x00, 0x02, 0x01, 0x02, 0x00, 0x03, 0x03, 0x04, 0x05, 0x00, 0x01, 0x06 },
        out.split().former.buf,
    );
}

test "decode OCSPStatusRequest" {
    var buf = [_]u8{ 0x00, 0x09, 0x00, 0x02, 0x01, 0x02, 0x00, 0x03, 0x03, 0x04, 0x05, 0x00, 0x01, 0x06 };
    var in = Bytes{ .buf = &buf };

    const got = try OCSPStatusRequest.decode(std.testing.allocator, &in);
    defer got.deinit();

    const id_list = got.responder_id_list.data.items;
    try std.testing.expectEqual(@as(usize, 2), id_list.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, id_list[0].data.items);
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0x04, 0x05 }, id_list[1].data.items);

    try std.testing.expectEqualSlices(u8, &.{0x06}, got.request_extensions.data.items);
}
