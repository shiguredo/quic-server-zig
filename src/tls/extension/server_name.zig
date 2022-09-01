const std = @import("std");
const meta = std.meta;
const VariableLengthVector = @import("../../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../../bytes.zig").Bytes;

const ServerNames = VariableLengthVector(ServerName, 65535);
const HostName = VariableLengthVector(u8, 65535);

/// https://www.rfc-editor.org/rfc/rfc6066#section-3
///
/// > The "extension_data" field of this extension SHALL contain "ServerNameList" where:
///
/// struct {
///     NameType name_type;
///     select (name_type) {
///         case host_name: HostName;
///     } name;
/// } ServerName;
///
/// enum {
///     host_name(0), (255)
/// } NameType;
///
/// opaque HostName<1..2^16-1>;
///
/// struct {
///     ServerName server_name_list<1..2^16-1>
/// } ServerNameList;
pub const ServerNameList = struct {
    server_name_list: ServerNames,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.server_name_list.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.server_name_list.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        return Self{
            .server_name_list = try ServerNames.decode(allocator, in),
        };
    }

    pub fn deinit(self: Self) void {
        self.server_name_list.deinit();
    }
};

test "encode ServerNameList" {
    const snl = ServerNameList{
        .server_name_list = try ServerNames.fromSlice(std.testing.allocator, &.{
            .{ .host_name = try HostName.fromSlice(std.testing.allocator, &.{ 0x01, 0x02 }) },
            .{ .host_name = try HostName.fromSlice(std.testing.allocator, &.{ 0x03, 0x04, 0x05 }) },
        }),
    };
    defer snl.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try snl.encode(&out);

    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x00, 0x0b, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x00, 0x03, 0x03, 0x04, 0x05 },
        out.split().former.buf,
    );
}

test "decode ServerNameList" {
    var buf = [_]u8{
        0x00, 0x0b, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x00, 0x03, 0x03, 0x04, 0x05,
    };
    var in = Bytes{ .buf = &buf };

    const got = try ServerNameList.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(usize, 2), got.server_name_list.data.items.len);
    const names = got.server_name_list.data.items;
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, names[0].host_name.data.items);
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0x04, 0x05 }, names[1].host_name.data.items);
}

/// https://www.rfc-editor.org/rfc/rfc6066#section-3
///
/// struct {
///     NameType name_type;
///     select (name_type) {
///         case host_name: HostName;
///     } name;
/// } ServerName;
///
/// opaque HostName<1..2^16-1>;
pub const ServerName = union(NameType) {
    host_name: HostName,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return @sizeOf(NameType.TagType) + switch (self) {
            .host_name => |h| h.encodedLength(),
        };
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.put(NameType.TagType, @enumToInt(self));
        switch (self) {
            .host_name => |h| try h.encode(out),
        }
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        const ty = try in.consume(NameType.TagType);
        return switch (@intToEnum(NameType, ty)) {
            .host_name => .{ .host_name = try HostName.decode(allocator, in) },
        };
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            .host_name => |h| h.deinit(),
        }
    }
};

test "encode ServerName" {
    const sn = ServerName{
        .host_name = try HostName.fromSlice(std.testing.allocator, &.{ 0x01, 0x02 }),
    };
    defer sn.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try sn.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x02, 0x01, 0x02 }, out.split().former.buf);
}

test "decode ServerName" {
    var buf = [_]u8{ 0x00, 0x00, 0x02, 0x01, 0x02 };
    var in = Bytes{ .buf = &buf };

    const got = try ServerName.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, got.host_name.data.items);
}

/// https://www.rfc-editor.org/rfc/rfc6066#section-3
///
/// enum {
///     host_name(0), (255)
/// } NameType;
const NameType = enum(u8) {
    host_name = 0,

    const Self = @This();
    const TagType = @typeInfo(Self).Enum.tag_type;
};
