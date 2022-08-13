const std = @import("std");
const mem = std.mem;
const ArrayList = std.ArrayList;

pub const ByteStream = struct {
    /// Data we're looking at.
    buf: []u8,
    /// The current index in the buffer.
    pos: usize = 0,

    const Self = @This();
    const Error = error{
        BufferTooShort,
    };

    /// Returns the number of remaining bytes in the buffer.
    pub fn remainingCapacity(self: Self) usize {
        return self.buf.len - self.pos;
    }

    /// Reads an integer of type `T` from the current position of the buffer,
    /// assuming it's represented in network byte order.
    /// It does NOT advance the position.
    pub fn peek(self: Self, comptime T: type) Error!T {
        if (@typeInfo(T) != .Int)
            @compileError("type `T` must be of integer, but got `" ++ @typeName(T) ++ "`");

        const rest = self.buf[self.pos..];
        if (rest.len < @sizeOf(T))
            return Error.BufferTooShort;

        return mem.readIntBig(T, rest[0..@sizeOf(T)]);
    }

    /// Reads an integer of type `T` from the current position of the buffer,
    /// assuming it's represented in network byte order.
    /// It DOES advance the position.
    pub fn get(self: *Self, comptime T: type) Error!T {
        if (@typeInfo(T) != .Int)
            @compileError("type `T` must be of integer, but got `" ++ @typeName(T) ++ "`");

        const v = try self.peek(T);
        self.pos += @sizeOf(T);
        return v;
    }

    pub fn peekBytesOwned(self: Self, allocator: mem.Allocator, size: usize) !ArrayList(u8) {
        const rest = self.buf[self.pos..];
        if (rest.len < size)
            return Error.BufferTooShort;

        var ret = try ArrayList(u8).initCapacity(allocator, size);
        ret.appendSliceAssumeCapacity(rest[0..size]);
        return ret;
    }

    pub fn getBytesOwned(self: *Self, allocator: mem.Allocator, size: usize) !ArrayList(u8) {
        const ret = try self.peekBytesOwned(allocator, size);
        self.pos += size;
        return ret;
    }

    /// Reads a variable-length integer from the current positon of the buffer.
    /// https://datatracker.ietf.org/doc/html/rfc9000#appendix-A.1
    pub fn getVarInt(self: *Self) Error!u64 {
        const length = parseVarintLength(try self.peek(u8));

        return switch (length) {
            1 => @intCast(u64, try self.get(u8)),
            2 => blk: {
                const v = try self.get(u16);
                break :blk @intCast(u64, v & 0x3fff);
            },
            4 => blk: {
                const v = try self.get(u32);
                break :blk @intCast(u64, v & 0x3fff_ffff);
            },
            8 => blk: {
                const v = try self.get(u64);
                break :blk v & 0x3fff_ffff_ffff_ffff;
            },
            else => unreachable,
        };
    }

    /// First reads a variable-length integer from the current position of the buffer,
    /// and then reads the next N bytes, where N is the value of variable-length integer we just read.
    /// It returns an AraryList composed of those N bytes.
    pub fn getBytesOwnedWithVarIntLength(self: *Self, allocator: mem.Allocator) !ArrayList(u8) {
        const len = try self.getVarInt();
        return self.getBytesOwned(allocator, @intCast(usize, len));
    }
};

/// Given the first byte, parses the length of variable-length integer,
/// as specified in https://datatracker.ietf.org/doc/html/rfc9000#section-16
pub fn parseVarintLength(first: u8) usize {
    return switch (first >> 6) {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        else => unreachable,
    };
}

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

test "ByteStream parse variable-length integer" {
    // test cases are taken from https://datatracker.ietf.org/doc/html/rfc9000#appendix-A.1
    {
        var buf = [_]u8{0x25};
        var s = ByteStream{ .buf = &buf };
        try std.testing.expectEqual(@as(u64, 37), try s.getVarInt());
    }

    {
        var buf = [_]u8{ 0x40, 0x25 };
        var s = ByteStream{ .buf = &buf };
        try std.testing.expectEqual(@as(u64, 37), try s.getVarInt());
    }

    {
        var buf = [_]u8{ 0x7b, 0xbd };
        var s = ByteStream{ .buf = &buf };
        try std.testing.expectEqual(@as(u64, 15293), try s.getVarInt());
    }

    {
        var buf = [_]u8{ 0x9d, 0x7f, 0x3e, 0x7d };
        var s = ByteStream{ .buf = &buf };
        try std.testing.expectEqual(@as(u64, 494878333), try s.getVarInt());
    }

    {
        var buf = [_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };
        var s = ByteStream{ .buf = &buf };
        try std.testing.expectEqual(@as(u64, 151288809941952652), try s.getVarInt());
    }
}

test "ByteStream getBytesOwnedWithVarIntLength" {
    {
        var buf = [_]u8{ 0b00_000001, 0x42 };
        var s = ByteStream{ .buf = &buf };
        const got = try s.getBytesOwnedWithVarIntLength(std.testing.allocator);
        defer got.deinit();
        try std.testing.expectEqualSlices(u8, buf[1..2], got.items);
    }

    {
        var buf = [_]u8{ 0b00_000001, 0x42, 0x99 };
        var s = ByteStream{ .buf = &buf };
        const got = try s.getBytesOwnedWithVarIntLength(std.testing.allocator);
        defer got.deinit();
        try std.testing.expectEqualSlices(u8, buf[1..2], got.items);
    }
}
