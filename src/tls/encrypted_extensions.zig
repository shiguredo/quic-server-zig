const std = @import("std");
const VariableLengthVector = @import("../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../bytes.zig").Bytes;
const Extension = @import("./extension.zig").Extension;

/// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.3.1
///
/// struct {
///     Extension extensions<0..2^16-1>;
/// } EncryptedExtensions;
pub const EncryptedExtensions = struct {
    pub const Extensions = VariableLengthVector(Extension(.server), 65535);

    extensions: Extensions,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.extensions.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.extensions.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        // TODO(magurotuna): implement
        _ = allocator;
        _ = in;
        return error.Unimplemented;
    }

    pub fn deinit(self: Self) void {
        self.extensions.deinit();
    }
};

test "encode EncryptedExtensions" {
    const ee = EncryptedExtensions{
        .extensions = try EncryptedExtensions.Extensions.fromSlice(std.testing.allocator, &.{}),
    };
    defer ee.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ee.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, out.split().former.buf);
}

test "encode EncryptedExtensions with extensions" {
    // It makes no sense to include supported_versions extension in EncryptedExtensions
    // since it is supposed to be included in ServerHello. But we do so just for testing purpose.
    const ee = EncryptedExtensions{
        .extensions = try EncryptedExtensions.Extensions.fromSlice(std.testing.allocator, &.{
            .{
                .supported_versions = .{
                    .selected_version = 0x03_04,
                },
            },
        }),
    };
    defer ee.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ee.encode(&out);

    // zig fmt: off
    try std.testing.expectEqualSlices(u8, &.{
        // The length of extensions
        0x00, 0x06,
        // supported_versions extension
        0x00, 0x2b,
        0x00, 0x02,
        0x03, 0x04,
    }, out.split().former.buf);
    // zig fmt: on
}
