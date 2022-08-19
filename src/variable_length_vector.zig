const std = @import("std");
const mem = std.mem;
const math = std.math;
const ArrayList = std.ArrayList;

pub fn VariableLengthVector(comptime T: type, comptime maximum_length: usize) type {
    return struct {
        data: ArrayList(T),

        const Self = @This();

        pub fn encode(self: Self, out: []u8) !usize {
            const LenType = comptime LengthType();
            const data_encode_size = blk: {
                var size: usize = 0;
                for (self.data.items) |item| {
                    // TODO(magurotuna): handle primitive types other than .Int
                    size += comptime if (@typeInfo(T) == .Int)
                        @sizeOf(T)
                    else
                        item.encode_size();
                }
                break :blk size;
            };
            if (out.len < @sizeOf(LenType) + data_encode_size)
                return error.BufferTooShort;

            var pos: usize = 0;

            mem.writeIntBig(LenType, out[0..@sizeOf(LenType)], @intCast(LenType, self.data.items.len));
            pos += @sizeOf(LenType);

            for (self.data.items) |item| {
                // TODO(magurotuna): handle primitive types other than .Int
                if (@typeInfo(T) == .Int) {
                    mem.writeIntSliceBig(T, out[pos..(pos + @sizeOf(T))], item);
                    pos += @sizeOf(T);
                } else {
                    pos += try item.encode(out[pos..]);
                }
            }

            return pos;
        }

        pub fn decode(allocator: std.mem.Allocator) !Self {
            // TODO(magurotuna): implement
            return Self{
                .data = ArrayList(T).init(allocator),
            };
        }

        pub fn deinit(self: Self) void {
            self.data.deinit();
        }

        fn LengthType() type {
            const types = [_]type{ u8, u16, u24, u32 };
            inline for (types) |ty| {
                if (maximum_length <= math.maxInt(ty)) {
                    return ty;
                }
            }
            @compileError("failed to get the type of length");
        }
    };
}

test "empty VariableLengthVector properly encoded" {
    const Opaque = VariableLengthVector(u8, 400);
    const v = Opaque{ .data = ArrayList(u8).init(std.testing.allocator) };
    defer v.deinit();
    var out: [1024]u8 = undefined;
    const written = try v.encode(&out);
    try std.testing.expectEqual(@as(usize, 2), written);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, out[0..written]);
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
    var out: [1024]u8 = undefined;
    const written = try v.encode(&out);
    try std.testing.expectEqual(@as(usize, 3), written);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x00, 0x01 }, out[0..written]);
}
