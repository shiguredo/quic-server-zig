const std = @import("std");
const mem = std.mem;

pub const ByteStream = struct {
    /// Data we're looking at.
    buf: []u8,
    /// The current index in the buffer.
    pos: usize = 0,

    const Self = @This();
    const Error = error {
        BufferTooShort,
    };

    pub fn peek(self: Self, comptime T: type) Error!T {
        const rest = self.buf[self.pos..];
        if (rest.len < @sizeOf(T))
            return Error.BufferTooShort;

        return mem.readIntBig(T, rest[0..@sizeOf(T)]);
    }

    pub fn get(self: *Self, comptime T: type) Error!T {
        const v = try self.peek(T);
        self.pos += @sizeOf(T);
        return v;
    }
};

test "ByteStream peek, get" {
    var buf = [_]u8{ 0x00, 0x01, 0x02 };

    var s = ByteStream{ .buf = &buf };

    try std.testing.expectEqual(@as(u8, 0), try s.peek(u8));
    try std.testing.expectEqual(@as(u8, 0), try s.get(u8));
    try std.testing.expectEqual(mem.readIntBig(u16, &[_]u8{ 0x01, 0x02 }), try s.peek(u16));
    try std.testing.expectEqual(mem.readIntBig(u16, &[_]u8{ 0x01, 0x02 }), try s.get(u16));

    try std.testing.expectError(error.BufferTooShort, s.peek(u8));
    try std.testing.expectError(error.BufferTooShort, s.get(u8));
}
