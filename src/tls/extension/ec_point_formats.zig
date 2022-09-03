const std = @import("std");
const VariableLengthVector = @import("../../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../../bytes.zig").Bytes;
const utils = @import("../../utils.zig");

/// https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1
///
/// > ec_point_formats (Supported Point Formats Extension): Indicates
/// > the set of point formats that the client can parse.  For this
/// > extension, the opaque extension_data field contains
/// > ECPointFormatList.
///
/// https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2
///
/// struct {
///     ECPointFormat ec_point_format_list<1..2^8-1>
/// } ECPointFormatList;
pub const ECPointFormatList = struct {
    ec_point_format_list: ECPointFormats,

    pub const ECPointFormats = VariableLengthVector(ECPointFormat, 255);

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.ec_point_format_list.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.ec_point_format_list.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        return Self{
            .ec_point_format_list = try ECPointFormats.decode(allocator, in),
        };
    }

    pub fn deinit(self: Self) void {
        self.ec_point_format_list.deinit();
    }
};

test "encode ECPointFormatList" {
    const ec_point_format_list = ECPointFormatList{
        .ec_point_format_list = try ECPointFormatList.ECPointFormats.fromSlice(
            std.testing.allocator,
            &.{
                .uncompressed,
                .deprecated,
            },
        ),
    };
    defer ec_point_format_list.deinit();
    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ec_point_format_list.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x02, 0x00, 0x01 }, out.split().former.buf);
}

test "decode ECPointFormatList" {
    var buf = [_]u8{ 0x02, 0x00, 0x01 };
    var in = Bytes{ .buf = &buf };

    const got = try ECPointFormatList.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqualSlices(
        ECPointFormat,
        &.{ .uncompressed, .deprecated },
        got.ec_point_format_list.data.items,
    );
}

/// https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2
///
/// enum {
///     uncompressed (0),
///     deprecated (1..2),
///     reserved (248..255)
/// } ECPointFormat;
pub const ECPointFormat = enum {
    uncompressed,
    deprecated,
    reserved,

    const Self = @This();
    const TagType = u8;

    pub fn encodedLength(self: Self) usize {
        _ = self;
        return utils.sizeOf(TagType);
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        const val: TagType = switch (self) {
            .uncompressed => 0,
            // TODO(magurotuna): Is is okay to always use `1` as a value for `deprecated`?
            .deprecated => 1,
            // TODO(magurotuna): Is is okay to always use `248` as a value for `reserved`?
            .reserved => 248,
        };
        try out.put(TagType, val);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        _ = allocator;

        return switch (try in.consume(TagType)) {
            0 => .uncompressed,
            1...2 => .deprecated,
            248...255 => .reserved,
            else => error.InvalidECPointFormat,
        };
    }

    pub fn deinit(self: Self) void {
        // no-op
        _ = self;
    }
};

test "encode ECPointFormat" {
    const ec_point_format = ECPointFormat.uncompressed;
    defer ec_point_format.deinit();
    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ec_point_format.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{0x00}, out.split().former.buf);
}

test "decode ECPointFormat" {
    var buf = [_]u8{0x00};
    var in = Bytes{ .buf = &buf };

    const got = try ECPointFormat.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(ECPointFormat.uncompressed, got);
}
