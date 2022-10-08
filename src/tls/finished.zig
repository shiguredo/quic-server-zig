const std = @import("std");
const BoundedArray = std.BoundedArray;
const VariableLengthVector = @import("../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../bytes.zig").Bytes;
const Extension = @import("./extension.zig").Extension;

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.4.4
///
/// struct {
///     opaque verify_data[Hash.length];
/// } Finished;
pub const Finished = struct {
    const max_verify_data_length = 128;
    pub const VerifyData = BoundedArray(u8, max_verify_data_length);

    verify_data: VerifyData,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.verify_data.len;
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.putBytes(self.verify_data.constSlice());
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        // TODO(magurotuna): implement
        _ = allocator;
        _ = in;
        return error.Unimplemented;
    }

    pub fn fromVerifyData(verify_data: []const u8) Self {
        std.debug.assert(verify_data.len <= max_verify_data_length);

        return .{
            .verify_data = VerifyData.fromSlice(verify_data) catch unreachable,
        };
    }

    pub fn deinit(self: Self) void {
        // no-op
        _ = self;
    }
};

test "encode Finished" {
    const fi = Finished{
        .verify_data = try Finished.VerifyData.fromSlice(&.{ 0x01, 0x02, 0x03 }),
    };
    defer fi.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try fi.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, out.split().former.buf);
}
