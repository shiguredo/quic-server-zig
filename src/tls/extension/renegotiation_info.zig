const std = @import("std");
const meta = std.meta;
const VariableLengthVector = @import("../../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../../bytes.zig").Bytes;

/// https://www.ietf.org/rfc/rfc5746.html#section-3.2
///
/// struct {
///     opaque renegotiated_connection<0..255>;
/// } RenegotiationInfo;
pub const RenegotiationInfo = struct {
    renegotiated_connection: RenegotiatedConnection,

    const Self = @This();
    const RenegotiatedConnection = VariableLengthVector(u8, 255);

    pub fn encodedLength(self: Self) usize {
        return self.renegotiated_connection.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.renegotiated_connection.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        return Self{
            .renegotiated_connection = try RenegotiatedConnection.decode(allocator, in),
        };
    }

    pub fn deinit(self: Self) void {
        self.renegotiated_connection.deinit();
    }
};

test "encode RenegotiatedConnection" {
    const ri = RenegotiationInfo{
        .renegotiated_connection = .{
            .data = blk: {
                var conn = std.ArrayList(u8).init(std.testing.allocator);
                errdefer conn.deinit();
                try conn.appendSlice(&.{ 0x01, 0x02, 0x03 });
                break :blk conn;
            },
        },
    };
    defer ri.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ri.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0x01, 0x02, 0x03 }, out.split().former.buf);
}

test "decode RenegotiatedConnection" {
    var buf = [_]u8{ 0x03, 0x01, 0x02, 0x03 };
    var in = Bytes{ .buf = &buf };

    const got = try RenegotiationInfo.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, got.renegotiated_connection.data.items);
}
