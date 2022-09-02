const std = @import("std");
const VariableLengthVector = @import("../../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../../bytes.zig").Bytes;

pub const ProtocolVersion = u16;
pub const Versions = VariableLengthVector(ProtocolVersion, 254);

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.1
///
/// uint16 ProtocolVersion;
///
/// struct {
///     select (Handshake.msg_type) {
///         case client_hello:
///              ProtocolVersion versions<2..254>;
///         case server_hello: /* and HelloRetryRequest */
///              ProtocolVersion selected_version;
///     };
/// } SupportedVersions;
pub const ServerSupportedVersions = struct {
    const Self = @This();

    selected_version: ProtocolVersion,

    pub fn encodedLength(self: Self) usize {
        _ = self;
        return @sizeOf(ProtocolVersion);
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.put(ProtocolVersion, self.selected_version);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        _ = allocator;
        const v = try in.consume(ProtocolVersion);
        return Self{
            .selected_version = v,
        };
    }

    pub fn deinit(self: Self) void {
        // no need to deinitialize
        _ = self;
    }
};

test "encode ServerSupportedVersions" {
    const sv = ServerSupportedVersions{
        .selected_version = 0x00_01,
    };
    defer sv.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try sv.encode(&out);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, out.split().former.buf);
}

test "decode ServerSupportedVersions" {
    var buf = [_]u8{ 0x00, 0x01 };
    var in = Bytes{ .buf = &buf };

    const got = try ServerSupportedVersions.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(ProtocolVersion, 0x00_01), got.selected_version);
}

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.1
///
/// uint16 ProtocolVersion;
///
/// struct {
///     select (Handshake.msg_type) {
///         case client_hello:
///              ProtocolVersion versions<2..254>;
///         case server_hello: /* and HelloRetryRequest */
///              ProtocolVersion selected_version;
///     };
/// } SupportedVersions;
pub const ClientSupportedVersions = struct {
    const Self = @This();

    versions: Versions,

    pub fn encodedLength(self: Self) usize {
        return self.versions.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.versions.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        const vs = try Versions.decode(allocator, in);
        return Self{
            .versions = vs,
        };
    }

    pub fn deinit(self: Self) void {
        self.versions.deinit();
    }
};

test "encode ClientSupportedVersions" {
    const sv = ClientSupportedVersions{
        .versions = try Versions.fromSlice(std.testing.allocator, &.{ 0x00_01, 0x02_03 }),
    };
    defer sv.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try sv.encode(&out);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x04, 0x00, 0x01, 0x02, 0x03 }, out.split().former.buf);
}

test "decode ClientSupportedVersions" {
    var buf = [_]u8{ 0x04, 0x00, 0x01, 0x02, 0x03 };
    var in = Bytes{ .buf = &buf };

    const got = try ClientSupportedVersions.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(usize, 2), got.versions.data.items.len);
    try std.testing.expectEqual(@as(ProtocolVersion, 0x00_01), got.versions.data.items[0]);
    try std.testing.expectEqual(@as(ProtocolVersion, 0x02_03), got.versions.data.items[1]);
}
