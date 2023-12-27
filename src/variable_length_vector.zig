const std = @import("std");
const mem = std.mem;
const math = std.math;
const ArrayList = std.ArrayList;
const Bytes = @import("./bytes.zig").Bytes;
const utils = @import("./utils.zig");

const VariableLengthVectorError = error{
    ExceedsLimit,
};

pub fn VariableLengthVector(comptime T: type, comptime maximum_length: usize) type {
    return struct {
        data: ArrayList(T),

        const Self = @This();

        const LengthType = blk: {
            const types = [_]type{ u8, u16, u24, u32 };
            inline for (types) |ty| {
                if (maximum_length <= math.maxInt(ty)) {
                    break :blk ty;
                }
            }
            @compileError("failed to get the type of length");
        };

        pub fn encodedLength(self: Self) usize {
            return utils.sizeOf(LengthType) + self.innerDataEncodedLength();
        }

        fn innerDataEncodedLength(self: Self) usize {
            var len: usize = 0;
            for (self.data.items) |item| {
                len += encodedLengthInner(T, item);
            }
            return len;
        }

        pub fn encode(self: Self, out: *Bytes) !void {
            try out.put(LengthType, @as(LengthType, @intCast(self.innerDataEncodedLength())));

            for (self.data.items) |item| {
                try encodeInner(T, item, out);
            }
        }

        pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
            const len = try in.consume(LengthType);
            var data = ArrayList(T).init(allocator);
            errdefer {
                if (comptime utils.hasDeinit(T)) {
                    for (data.items) |item| {
                        item.deinit();
                    }
                }
                data.deinit();
            }

            // Create new `Bytes` that only views the range being decoded as a `VariableLengthVector`.
            var new_bytes = Bytes{ .buf = try in.consumeBytes(len) };

            while (!new_bytes.reachedEnd()) {
                const item = try decodeInner(T, allocator, &new_bytes);
                errdefer {
                    if (comptime utils.hasDeinit(T)) item.deinit();
                }

                try data.append(item);
            }

            return Self{
                .data = data,
            };
        }

        /// Deinitialize the inner data structure.
        /// If the item type `T` needs to be deinitialized, each item's `deinit` method will be called too.
        pub fn deinit(self: Self) void {
            if (comptime utils.hasDeinit(T)) {
                for (self.data.items) |item| {
                    item.deinit();
                }
            }

            self.data.deinit();
        }

        /// Create a new `VariableLengthVector` with the given items.
        /// Note that the ownership of each item will be moved to the created `VariableLengthVector`.
        pub fn fromSlice(allocator: std.mem.Allocator, items: []const T) !Self {
            if (items.len > maximum_length)
                return VariableLengthVectorError.ExceedsLimit;

            var data = try ArrayList(T).initCapacity(allocator, items.len);
            errdefer data.deinit();

            data.appendSliceAssumeCapacity(items);
            return Self{ .data = data };
        }

        /// Append the given item to the `VariableLengthVector`.
        /// Note that the ownership of the item will be moved to the `VariableLengthVector`.
        pub fn append(self: *Self, item: T) !void {
            if (self.data.items.len == maximum_length)
                return VariableLengthVectorError.ExceedsLimit;

            try self.data.append(item);
        }

        /// Append the given items to the `VariableLengthVector`.
        /// Note that the ownership of the item will be moved to the `VariableLengthVector`.
        pub fn appendSlice(self: *Self, items: []const T) !void {
            if (self.data.items.len + items.len > maximum_length)
                return VariableLengthVectorError.ExceedsLimit;

            try self.data.appendSlice(items);
        }
    };
}

fn encodeInner(comptime T: type, value: T, out: *Bytes) !void {
    switch (@typeInfo(T)) {
        .Int => try out.put(T, value),
        .Array => |arr| {
            for (value) |v| {
                try encodeInner(arr.child, v, out);
            }
        },
        // TODO(magurotuna): handle other primitive types
        else => try value.encode(out),
    }
}

fn decodeInner(comptime T: type, allocator: std.mem.Allocator, in: *Bytes) !T {
    return switch (@typeInfo(T)) {
        .Int => try in.consume(T),
        .Array => |arr| blk: {
            var ret: [arr.len]arr.child = undefined;
            inline for (ret) |*item| {
                const v = try decodeInner(arr.child, allocator, in);
                errdefer {
                    if (comptime utils.hasDeinit(arr.child)) v.deinit();
                }
                item.* = v;
            }
            break :blk ret;
        },
        // TODO(magurotuna): handle other primitive types
        else => try T.decode(allocator, in),
    };
}

fn encodedLengthInner(comptime T: type, value: T) usize {
    return switch (@typeInfo(T)) {
        .Int => utils.sizeOf(T),
        .Array => |arr| blk: {
            var len: usize = 0;
            for (value) |v| {
                len += encodedLengthInner(arr.child, v);
            }
            break :blk len;
        },
        // TODO(magurotuna): handle other primitive types
        else => value.encodedLength(),
    };
}

// For testing
const Foo = struct {
    data: ArrayList(u8),

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return utils.sizeOf(u8) * self.data.items.len;
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.putBytes(self.data.items);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        const len = in.buf.len;
        const all = try in.consumeBytesOwned(allocator, len);
        errdefer all.deinit();
        return Self{ .data = all };
    }

    pub fn deinit(self: Self) void {
        self.data.deinit();
    }
};

test "encode empty VariableLengthVector of u8" {
    const Opaque = VariableLengthVector(u8, 400);
    const v = try Opaque.fromSlice(std.testing.allocator, &.{});
    defer v.deinit();
    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };
    try v.encode(&out);
    try std.testing.expectEqual(@as(usize, 2), out.pos);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, out.split().former.buf);
}

test "encode non-empty VariableLengthVector of u8" {
    const Opaque = VariableLengthVector(u8, 255);
    const v = try Opaque.fromSlice(std.testing.allocator, &.{ 0x00, 0x01 });
    defer v.deinit();
    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };
    try v.encode(&out);
    try std.testing.expectEqual(@as(usize, 3), out.pos);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x00, 0x01 }, out.split().former.buf);
}

test "encode non-empty VariableLengthVector of a type that implements its own encode method" {
    const Vec = VariableLengthVector(Foo, 255);
    var data = ArrayList(Foo).init(std.testing.allocator);
    try data.append(foo: {
        var f = ArrayList(u8).init(std.testing.allocator);
        errdefer f.deinit();
        try f.append(0x00);
        break :foo .{ .data = f };
    });
    try data.append(foo: {
        var f = ArrayList(u8).init(std.testing.allocator);
        errdefer f.deinit();
        try f.append(0x01);
        try f.append(0x02);
        break :foo .{ .data = f };
    });

    const v = Vec{ .data = data };
    defer v.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };
    try v.encode(&out);
    try std.testing.expectEqual(@as(usize, 4), out.pos);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x00, 0x01, 0x02 }, out.split().former.buf);
}

test "decode empty VariableLengthVector of u8" {
    const Opaque = VariableLengthVector(u8, 255);

    // Only contains the length
    var buf = [_]u8{0x00};
    var in = Bytes{ .buf = &buf };

    const got = try Opaque.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqualSlices(u8, &[_]u8{}, got.data.items);
}

test "decode non-empty VariableLengthVector of u8" {
    const Opaque = VariableLengthVector(u8, 255);

    var buf = [_]u8{ 0x02, 0x00, 0x01 };
    var in = Bytes{ .buf = &buf };

    const got = try Opaque.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, got.data.items);
}

test "decode non-empty VariableLengthVector of a type that needs to be deinitialized" {
    const Vec = VariableLengthVector(Foo, 255);

    var buf = [_]u8{ 0x02, 0x00, 0x01 };
    var in = Bytes{ .buf = &buf };

    const got = try Vec.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(usize, 1), got.data.items.len);
    const foo_data = got.data.items[0].data.items;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, foo_data);
}

test "create a new VariableLengthVector with fromSlice" {
    const Vec = VariableLengthVector(u8, 2);

    {
        const v = try Vec.fromSlice(std.testing.allocator, &.{ 0x01, 0x02 });
        defer v.deinit();
        try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, v.data.items);
    }

    {
        try std.testing.expectError(
            VariableLengthVectorError.ExceedsLimit,
            Vec.fromSlice(std.testing.allocator, &.{ 0x01, 0x02, 0x03 }),
        );
    }
}

test "append items to a VariableLengthVector" {
    const Vec = VariableLengthVector(u8, 3);

    var v = try Vec.fromSlice(std.testing.allocator, &.{});
    defer v.deinit();

    try v.append(0x01);
    try v.appendSlice(&.{ 0x02, 0x03 });
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, v.data.items);

    try std.testing.expectError(
        VariableLengthVectorError.ExceedsLimit,
        v.append(0x04),
    );
    try std.testing.expectError(
        VariableLengthVectorError.ExceedsLimit,
        v.appendSlice(&.{0x04}),
    );
}
