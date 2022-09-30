const std = @import("std");
const bytes = @import("../bytes.zig");

const frame_type = 0x01;

const Self = @This();

pub fn encodedLength(self: Self) usize {
    _ = self;
    return bytes.varIntLength(frame_type);
}

pub fn encode(self: Self, out: *bytes.Bytes) !void {
    _ = self;
    try out.putVarInt(frame_type);
}

pub fn decode(allocator: std.mem.Allocator, in: *bytes.Bytes) !Self {
    _ = allocator;
    const ty = try in.consumeVarInt();
    std.debug.assert(ty == frame_type);
    return Self{};
}

pub fn deinit(self: Self) void {
    // no-op
    _ = self;
}

test "encode PING frame" {
    const ping = Self{};
    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try std.testing.expectEqual(@as(usize, 1), ping.encodedLength());

    try ping.encode(&out);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x01}, out.split().former.buf);
}

test "decode PING frame" {
    var buf = [_]u8{0x01};
    var in = bytes.Bytes{ .buf = &buf };

    const got = try Self.decode(std.testing.allocator, &in);
    defer got.deinit();
    // Just confirm that it's successfully parsed as Ping.
}
