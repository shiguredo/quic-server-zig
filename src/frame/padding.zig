const std = @import("std");
const bytes = @import("../bytes.zig");

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-padding-frames
///
/// PADDING Frame {
///   Type (i) = 0x00,
/// }
pub const Padding = struct {
    frame_type: u64 = frame_type,

    const Self = @This();
    const frame_type = 0x00;

    pub fn encodedLength(self: Self) usize {
        return bytes.varIntLength(self.frame_type);
    }

    pub fn encode(self: Self, out: *bytes.Bytes) !void {
        try out.putVarInt(self.frame_type);
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
};

test "encode PADDING frame" {
    const padding = Padding{};
    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try std.testing.expectEqual(@as(usize, 1), padding.encodedLength());

    try padding.encode(&out);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, out.split().former.buf);
}

test "decode PADDING frame" {
    var buf = [_]u8{0x00};
    var in = bytes.Bytes{ .buf = &buf };

    const got = try Padding.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(u64, 0x00), got.frame_type);
}
