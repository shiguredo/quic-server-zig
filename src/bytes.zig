const std = @import("std");
const mem = std.mem;
const ArrayList = std.ArrayList;
const utils = @import("./utils.zig");

/// A wrapper around a binary slice, providing several operations useful for reading and manipulating it.
/// Note that this struct does NOT copy the given binary slice, but just references it.
/// So it's the caller's responsibility to make the value of type `Bytes` not outlive the referenced slice.
pub const Bytes = struct {
    /// Data we're looking at.
    buf: []u8,
    /// The current index in the buffer.
    pos: usize = 0,

    const Self = @This();
    pub const Error = error{
        BufferTooShort,
        OutOfRange,
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
        if (rest.len < utils.sizeOf(T))
            return Error.BufferTooShort;

        return mem.readIntBig(T, rest[0..utils.sizeOf(T)]);
    }

    /// Reads an integer of type `T` from the current position of the buffer,
    /// assuming it's represented in network byte order.
    /// It DOES advance the position.
    pub fn consume(self: *Self, comptime T: type) Error!T {
        if (@typeInfo(T) != .Int)
            @compileError("type `T` must be of integer, but got `" ++ @typeName(T) ++ "`");

        const v = try self.peek(T);
        self.pos += utils.sizeOf(T);
        return v;
    }

    /// Reads `size` bytes from the current position without advancing the position,
    /// and returns the bytes as `ArrayList(u8)` so the caller owns it.
    pub fn peekBytesOwned(self: Self, allocator: mem.Allocator, size: usize) !ArrayList(u8) {
        const slice = try self.peekBytes(size);
        var ret = try ArrayList(u8).initCapacity(allocator, size);
        ret.appendSliceAssumeCapacity(slice);
        return ret;
    }

    /// Reads `size` bytes from the current position without advancing the position,
    /// and returns the bytes as a slice without allocating any additional memory.
    pub fn peekBytes(self: Self, size: usize) ![]u8 {
        const rest = self.buf[self.pos..];
        if (rest.len < size)
            return Error.BufferTooShort;

        return rest[0..size];
    }

    /// Reads `size` bytes from the current position, advances the position,
    /// and returns the bytes as `ArrayList(u8)` so the caller owns it.
    pub fn consumeBytesOwned(self: *Self, allocator: mem.Allocator, size: usize) !ArrayList(u8) {
        const ret = try self.peekBytesOwned(allocator, size);
        self.pos += size;
        return ret;
    }

    /// Reads `size` bytes from the current position, advances the position,
    /// and returns the bytes as a slice without allocating any additional memory.
    pub fn consumeBytes(self: *Self, size: usize) ![]u8 {
        const ret = try self.peekBytes(size);
        self.pos += size;
        return ret;
    }

    /// Reads bytes until the end of the buffer without advancing the position,
    /// and returns the bytes as a slice without allocating any additional memory.
    pub fn peekBytesUntilEnd(self: Self) ![]u8 {
        if (self.pos > self.buf.len)
            return Error.OutOfRange;

        return self.buf[self.pos..];
    }

    /// Reads bytes until the end of the buffer without advancing the position,
    /// and returns the bytes as `ArrayList(u8)` so the caller owns it.
    pub fn peekBytesUntilEndOwned(self: Self, allocator: mem.Allocator) !ArrayList(u8) {
        const slice = try self.peekBytesUntilEnd();
        var ret = try ArrayList(u8).initCapacity(allocator, slice.len);
        ret.appendSliceAssumeCapacity(slice);
        return ret;
    }

    /// Reads bytes until the end of the buffer, advances the position,
    /// and returns the bytes as a slice without allocating any additional memory.
    pub fn consumeBytesUntilEnd(self: *Self) ![]u8 {
        const ret = try self.peekBytesUntilEnd();
        self.pos = self.buf.len;
        return ret;
    }

    /// Reads bytes until the end of the buffer, advances the position,
    /// and returns the bytes as `ArrayList(u8)` so the caller owns it.
    pub fn consumeBytesUntilEndOwned(self: *Self, allocator: mem.Allocator) !ArrayList(u8) {
        const ret = try self.peekBytesUntilEndOwned(allocator);
        self.pos = self.buf.len;
        return ret;
    }

    /// Reads a variable-length integer from the current positon of the buffer,
    /// without advancing the position.
    /// https://datatracker.ietf.org/doc/html/rfc9000#appendix-A.1
    pub fn peekVarInt(self: Self) Error!u64 {
        const length = parseVarIntLength(try self.peek(u8));

        return switch (length) {
            1 => @intCast(u64, try self.peek(u8)),
            2 => blk: {
                const v = try self.peek(u16);
                break :blk @intCast(u64, v & 0x3fff);
            },
            4 => blk: {
                const v = try self.peek(u32);
                break :blk @intCast(u64, v & 0x3fff_ffff);
            },
            8 => blk: {
                const v = try self.peek(u64);
                break :blk v & 0x3fff_ffff_ffff_ffff;
            },
            else => unreachable,
        };
    }

    /// Reads a variable-length integer from the current positon of the buffer,
    /// and advances the position.
    /// https://datatracker.ietf.org/doc/html/rfc9000#appendix-A.1
    pub fn consumeVarInt(self: *Self) Error!u64 {
        const length = parseVarIntLength(try self.peek(u8));
        const ret = try self.peekVarInt();
        self.pos += length;
        return ret;
    }

    /// First reads a variable-length integer from the current position of the buffer,
    /// and then reads the next N bytes, where N is the value of variable-length integer we just read.
    /// It returns an AraryList composed of those N bytes.
    pub fn consumeBytesOwnedWithVarIntLength(self: *Self, allocator: mem.Allocator) !ArrayList(u8) {
        const len = try self.consumeVarInt();
        return self.consumeBytesOwned(allocator, @intCast(usize, len));
    }

    /// Writes the given integer into the current position of the buffer, advancing the position.
    pub fn put(self: *Self, comptime T: type, value: T) Error!void {
        if (@typeInfo(T) != .Int)
            @compileError("type `T` must be of integer, but got `" ++ @typeName(T) ++ "`");

        var rest = self.buf[self.pos..];
        if (rest.len < utils.sizeOf(T))
            return Error.BufferTooShort;

        mem.writeIntBig(T, rest[0..utils.sizeOf(T)], value);
        self.pos += utils.sizeOf(T);
    }

    /// Writes the given bytes into the current position of the buffer, advancing the position.
    pub fn putBytes(self: *Self, bytes: []const u8) Error!void {
        var rest = self.buf[self.pos..];
        if (rest.len < bytes.len)
            return Error.BufferTooShort;

        mem.copy(u8, rest, bytes);
        self.pos += bytes.len;
    }

    /// Writes the given integer as variable-length encoded, into the current position of the buffer,
    /// advancing the position.
    pub fn putVarInt(self: *Self, value: u64) Error!void {
        const length = varIntLength(value);

        var rest = self.buf[self.pos..];
        if (rest.len < length)
            return Error.BufferTooShort;

        switch (length) {
            1 => try self.put(u8, @truncate(u8, value) | (0b00 << 6)),
            2 => try self.put(u16, @truncate(u16, value) | (0b01 << 14)),
            4 => try self.put(u32, @truncate(u32, value) | (0b10 << 30)),
            8 => try self.put(u64, value | (0b11 << 62)),
            else => unreachable,
        }
    }

    pub const Split = struct {
        former: Bytes,
        latter: Bytes,
    };

    /// Creates two new Bytes by splitting the internal buffer at the current position.
    pub fn split(self: Self) Split {
        return .{
            .former = .{ .buf = self.buf[0..self.pos] },
            .latter = .{ .buf = self.buf[self.pos..] },
        };
    }
};

/// Given the first byte, parses the length of variable-length integer,
/// as specified in https://datatracker.ietf.org/doc/html/rfc9000#section-16
pub fn parseVarIntLength(first: u8) usize {
    return switch (first >> 6) {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        else => unreachable,
    };
}

/// Given the original value, returns the length in byte that is necessary
/// to represent the value in variable-length integer, as specified in
/// https://datatracker.ietf.org/doc/html/rfc9000#section-16
pub fn varIntLength(value: u64) usize {
    return if (value <= 63)
        @as(usize, 1)
    else if (value <= 16383)
        @as(usize, 2)
    else if (value <= 1073741823)
        @as(usize, 4)
    else if (value <= 4611686018427387903)
        @as(usize, 8)
    else
        unreachable;
}

test "Bytes peek, consume" {
    var buf = [_]u8{ 0x00, 0x01, 0x02 };

    var b = Bytes{ .buf = &buf };

    try std.testing.expectEqual(@as(u8, 0), try b.peek(u8));
    try std.testing.expectEqual(@as(u8, 0), try b.consume(u8));
    try std.testing.expectEqual(mem.readIntBig(u16, &[_]u8{ 0x01, 0x02 }), try b.peek(u16));
    try std.testing.expectEqual(mem.readIntBig(u16, &[_]u8{ 0x01, 0x02 }), try b.consume(u16));

    try std.testing.expectError(Bytes.Error.BufferTooShort, b.peek(u8));
    try std.testing.expectError(Bytes.Error.BufferTooShort, b.consume(u8));
}

test "consumeBytes" {
    var buf = [_]u8{ 0x00, 0x01, 0x02 };

    var b = Bytes{ .buf = &buf };

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, try b.consumeBytes(2));
    try std.testing.expectEqualSlices(u8, &[_]u8{0x02}, try b.consumeBytes(1));
    try std.testing.expectError(Bytes.Error.BufferTooShort, b.consumeBytes(1));
}

test "peekBytesUntilEnd, consumeBytesUntilEnd" {
    var buf = [_]u8{ 0x00, 0x01, 0x02 };

    var b = Bytes{ .buf = &buf };

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01, 0x02 }, try b.peekBytesUntilEnd());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01, 0x02 }, try b.consumeBytesUntilEnd());
    try std.testing.expectEqualSlices(u8, &[_]u8{}, try b.peekBytesUntilEnd());
    try std.testing.expectEqualSlices(u8, &[_]u8{}, try b.consumeBytesUntilEnd());
}

test "Bytes parse variable-length integer" {
    // Test cases are taken from https://datatracker.ietf.org/doc/html/rfc9000#appendix-A.1
    {
        var buf = [_]u8{0x25};
        var b = Bytes{ .buf = &buf };
        try std.testing.expectEqual(@as(u64, 37), try b.consumeVarInt());
    }

    {
        var buf = [_]u8{ 0x40, 0x25 };
        var b = Bytes{ .buf = &buf };
        try std.testing.expectEqual(@as(u64, 37), try b.consumeVarInt());
    }

    {
        var buf = [_]u8{ 0x7b, 0xbd };
        var b = Bytes{ .buf = &buf };
        try std.testing.expectEqual(@as(u64, 15293), try b.consumeVarInt());
    }

    {
        var buf = [_]u8{ 0x9d, 0x7f, 0x3e, 0x7d };
        var b = Bytes{ .buf = &buf };
        try std.testing.expectEqual(@as(u64, 494878333), try b.consumeVarInt());
    }

    {
        var buf = [_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };
        var b = Bytes{ .buf = &buf };
        try std.testing.expectEqual(@as(u64, 151288809941952652), try b.consumeVarInt());
    }
}

test "Bytes consumeBytesOwnedWithVarIntLength" {
    {
        var buf = [_]u8{ 0b00_000001, 0x42 };
        var b = Bytes{ .buf = &buf };
        const got = try b.consumeBytesOwnedWithVarIntLength(std.testing.allocator);
        defer got.deinit();
        try std.testing.expectEqualSlices(u8, buf[1..2], got.items);
    }

    {
        var buf = [_]u8{ 0b00_000001, 0x42, 0x99 };
        var b = Bytes{ .buf = &buf };
        const got = try b.consumeBytesOwnedWithVarIntLength(std.testing.allocator);
        defer got.deinit();
        try std.testing.expectEqualSlices(u8, buf[1..2], got.items);
    }
}

test "Bytes put" {
    var buf: [3]u8 = undefined;
    var b = Bytes{ .buf = &buf };
    try b.put(u8, 0x01);
    try b.put(u16, 0x0203);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, &buf);
}

test "Bytes putBytes" {
    var buf: [3]u8 = undefined;
    var b = Bytes{ .buf = &buf };

    try std.testing.expectError(Bytes.Error.BufferTooShort, b.putBytes(&[_]u8{ 0x01, 0x02, 0x03, 0x04 }));

    try b.putBytes(&[_]u8{ 0x01, 0x02, 0x03 });
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, &buf);
}

test "Bytes putVarInt" {
    // Test cases are taken from https://datatracker.ietf.org/doc/html/rfc9000#appendix-A.1
    {
        var buf: [1]u8 = undefined;
        var b = Bytes{ .buf = &buf };
        try b.putVarInt(37);
        try std.testing.expectEqualSlices(u8, &[_]u8{0x25}, &buf);
    }

    {
        var buf: [2]u8 = undefined;
        var b = Bytes{ .buf = &buf };
        try b.putVarInt(15293);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x7b, 0xbd }, &buf);
    }

    {
        var buf: [4]u8 = undefined;
        var b = Bytes{ .buf = &buf };
        try b.putVarInt(494878333);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d }, &buf);
    }

    {
        var buf: [8]u8 = undefined;
        var b = Bytes{ .buf = &buf };
        try b.putVarInt(151288809941952652);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c }, &buf);
    }
}
