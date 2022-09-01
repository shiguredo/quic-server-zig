const std = @import("std");
const VariableLengthVector = @import("../../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../../bytes.zig").Bytes;

/// https://www.rfc-editor.org/rfc/rfc8449#section-4
///
/// > The ExtensionData of the "record_size_limit" extension is RecordSizeLimit:
///
/// uint16 RecordSizeLimit;
pub const RecordSizeLimit = struct {
    record_size_limit: Limit,

    const Self = @This();
    const Limit = u16;

    pub fn encodedLength(self: Self) usize {
        _ = self;
        return @sizeOf(Limit);
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.put(Limit, self.record_size_limit);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        _ = allocator;
        return Self{
            .record_size_limit = try in.consume(Limit),
        };
    }

    pub fn deinit(self: Self) void {
        // no-op
        _ = self;
    }
};

test "encode RecordSizeLimit" {
    const limit = RecordSizeLimit{
        .record_size_limit = 0x42,
    };
    defer limit.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try limit.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x42 }, out.split().former.buf);
}

test "decode RecordSizeLimit" {
    var buf = [_]u8{ 0x00, 0x42 };
    var in = Bytes{ .buf = &buf };

    const got = try RecordSizeLimit.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(u16, 0x42), got.record_size_limit);
}
