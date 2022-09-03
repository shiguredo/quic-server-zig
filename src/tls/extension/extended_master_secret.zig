const std = @import("std");
const VariableLengthVector = @import("../../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../../bytes.zig").Bytes;

/// https://www.rfc-editor.org/rfc/rfc7627.html#section-5.1
///
/// > The "extension_data" field of this extension is empty.  Thus, the entire
/// > encoding of the extension is 00 17 00 00 (in hexadecimal.)
pub const ExtendedMasterSecret = struct {
    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        _ = self;
        return 0;
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        // no-op
        _ = self;
        _ = out;
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        _ = allocator;
        _ = in;
        return Self{};
    }

    pub fn deinit(self: Self) void {
        // no-op
        _ = self;
    }
};

test "encode ExtendedMasterSecret" {
    const sec = ExtendedMasterSecret{};
    defer sec.deinit();
    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try sec.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{}, out.split().former.buf);
}

test "decode ExtendedMasterSecret" {
    var buf = [_]u8{};
    var in = Bytes{ .buf = &buf };

    const got = try ExtendedMasterSecret.decode(std.testing.allocator, &in);
    defer got.deinit();
}
