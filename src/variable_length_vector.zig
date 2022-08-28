const std = @import("std");
const mem = std.mem;
const math = std.math;
const ArrayList = std.ArrayList;
const Bytes = @import("./bytes.zig").Bytes;

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
            var len: usize = 0;
            len += @sizeOf(LengthType);
            for (self.data.items) |item| {
                // TODO(magurotuna): handle primitive types other than .Int
                len += comptime if (@typeInfo(T) == .Int)
                    @sizeOf(T)
                else
                    item.encodedLength();
            }
            return len;
        }

        pub fn encode(self: Self, out: *Bytes) !void {
            try out.put(LengthType, @intCast(LengthType, self.data.items.len));

            for (self.data.items) |item| {
                // TODO(magurotuna): handle primitive types other than .Int
                if (@typeInfo(T) == .Int) {
                    try out.put(T, item);
                } else {
                    try item.encode(out);
                }
            }
        }

        pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
            const len = try in.consume(LengthType);
            var data = try ArrayList(T).initCapacity(@intCast(usize, len));
            errdefer data.deinit();

            var i: usize = 0;
            while (i < len) : (i += 1) {
                // TODO(magurotuna): handle primitive types other than .Int
                const item = comptime if (@typeInfo(T) == .Int)
                    try in.consume(T)
                else
                    try T.decode(allocator, in);

                // `data` must have enough space to accomodate `len` items since we create via `initCapacity`,
                // thus `appendAssumeCapacity` is safe here.
                data.appendAssumeCapacity(item);
            }

            return Self{
                .data = data,
            };
        }

        pub fn deinit(self: Self) void {
            self.data.deinit();
        }
    };
}

test "empty VariableLengthVector properly encoded" {
    const Opaque = VariableLengthVector(u8, 400);
    const v = Opaque{ .data = ArrayList(u8).init(std.testing.allocator) };
    defer v.deinit();
    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };
    try v.encode(&out);
    try std.testing.expectEqual(@as(usize, 2), out.pos);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, out.split().former.buf);
}

test "non-empty VariableLengthVector properly encoded" {
    const Opaque = VariableLengthVector(u8, 255);
    const data = blk: {
        var v = ArrayList(u8).init(std.testing.allocator);
        try v.append(0x00);
        try v.append(0x01);
        break :blk v;
    };
    const v = Opaque{ .data = data };
    defer v.deinit();
    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };
    try v.encode(&out);
    try std.testing.expectEqual(@as(usize, 3), out.pos);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x00, 0x01 }, out.split().former.buf);
}
