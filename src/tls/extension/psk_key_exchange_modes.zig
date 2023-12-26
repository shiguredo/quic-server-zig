const std = @import("std");
const meta = std.meta;
const VariableLengthVector = @import("../../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../../bytes.zig").Bytes;
const utils = @import("../../utils.zig");

const KeModes = VariableLengthVector(PskKeyExchangeMode, 255);

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.9
///
/// struct {
///     PskKeyExchangeMode ke_modes<1..255>;
/// } PskKeyExchangeModes;
pub const PskKeyExchangeModes = struct {
    ke_modes: KeModes,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.ke_modes.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.ke_modes.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        return Self{
            .ke_modes = try KeModes.decode(allocator, in),
        };
    }

    pub fn deinit(self: Self) void {
        self.ke_modes.deinit();
    }
};

test "encode PskKeyExchangeModes" {
    const modes = PskKeyExchangeModes{
        .ke_modes = try KeModes.fromSlice(std.testing.allocator, &.{ .psk_dhe_ke, .psk_ke }),
    };
    defer modes.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try modes.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x02, 0x01, 0x00 }, out.split().former.buf);
}

test "decode PskKeyExchangeModes" {
    var buf = [_]u8{ 0x02, 0x01, 0x00 };
    var in = Bytes{ .buf = &buf };

    const got = try PskKeyExchangeModes.decode(std.testing.allocator, &in);
    defer got.deinit();

    const modes = got.ke_modes.data.items;
    try std.testing.expectEqual(@as(usize, 2), modes.len);
    try std.testing.expectEqual(PskKeyExchangeMode.psk_dhe_ke, modes[0]);
    try std.testing.expectEqual(PskKeyExchangeMode.psk_ke, modes[1]);
}

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.9
///
/// enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
pub const PskKeyExchangeMode = enum(u8) {
    psk_ke = 0,
    psk_dhe_ke = 1,

    const Self = @This();
    const TagType = @typeInfo(Self).Enum.tag_type;

    pub fn encodedLength(self: Self) usize {
        _ = self;
        return utils.sizeOf(TagType);
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.put(TagType, @intFromEnum(self));
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        _ = allocator;
        const val = try in.consume(TagType);
        return meta.intToEnum(Self, val);
    }

    pub fn deinit(self: Self) void {
        // no-op
        _ = self;
    }
};

test "encode PskKeyExchangeMode" {
    const key = PskKeyExchangeMode.psk_dhe_ke;
    defer key.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try key.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{0x01}, out.split().former.buf);
}

test "decode PskKeyExchangeMode" {
    var buf = [_]u8{0x01};
    var in = Bytes{ .buf = &buf };

    const got = try PskKeyExchangeMode.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(PskKeyExchangeMode.psk_dhe_ke, got);
}
