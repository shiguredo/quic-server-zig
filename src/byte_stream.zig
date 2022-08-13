const std = @import("std");

pub const ByteStream = struct {
    /// Data we're looking at.
    buf: []u8,
    /// The current index in the buffer.
    pos: usize = 0,

    const Self = @This();
    const Error = error {
        BufferTooShort,
    };

    pub fn peekU8(self: Self) Error!u8 {
        const rest = self.buf[self.pos..];
        if (rest.len < @sizeOf(u8))
            return error.BufferTooShort;

        return rest[0];
    }

    pub fn getU8(self: *Self) Error!u8 {
        const v = try self.peekU8();
        self.pos += @sizeOf(u8);
        return v;
    }
};

test "ByteStream peekU8, getU8" {
    var buf = [_]u8{ 0x00, 0x01, 0x02 };

    var s = ByteStream{ .buf = &buf };

    try std.testing.expectEqual(@as(u8, 0), try s.peekU8());
    try std.testing.expectEqual(@as(u8, 0), try s.getU8());
    try std.testing.expectEqual(@as(u8, 1), try s.peekU8());
    try std.testing.expectEqual(@as(u8, 1), try s.getU8());
    try std.testing.expectEqual(@as(u8, 2), try s.peekU8());
    try std.testing.expectEqual(@as(u8, 2), try s.getU8());

    try std.testing.expectError(error.BufferTooShort, s.peekU8());
    try std.testing.expectError(error.BufferTooShort, s.getU8());
}
