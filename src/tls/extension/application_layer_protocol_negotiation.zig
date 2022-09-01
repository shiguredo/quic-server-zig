const std = @import("std");
const VariableLengthVector = @import("./variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("./bytes.zig").Bytes;

pub const ProtocolNames = VariableLengthVector(ProtocolName, 65535);

/// https://www.rfc-editor.org/rfc/rfc7301#section-3.1
///
/// opaque ProtocolName<1..2^8-1>;
pub const ProtocolName = VariableLengthVector(u8, 255);

/// https://www.rfc-editor.org/rfc/rfc7301#section-3.1
///
/// struct {
///     ProtocolName protocol_name_list<2..2^16-1>
/// } ProtocolNameList;
///
/// > The "extension_data" field of the ("application_layer_protocol_negotiation(16)") extension
/// > SHALL contain a "ProtocolNameList" value.
///
/// Also known as "ALPN".
pub const ApplicationLayerProtocolNegotiation = struct {
    protocol_name_list: ProtocolNames,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.protocol_name_list.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.protocol_name_list.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        return Self{
            .protocol_name_list = try ProtocolNames.decode(allocator, in),
        };
    }

    pub fn deinit(self: Self) void {
        self.protocol_name_list.deinit();
    }
};

test "encode ApplicationLayerProtocolNegotiation" {
    const alpn = ApplicationLayerProtocolNegotiation{
        .protocol_name_list = try ProtocolNames.fromSlice(std.testing.allocator, &.{
            try ProtocolName.fromSlice(std.testing.allocator, &.{ 0x01, 0x02 }),
            try ProtocolName.fromSlice(std.testing.allocator, &.{ 0x03, 0x04, 0x05 }),
        }),
    };
    defer alpn.deinit();
    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try alpn.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x07, 0x02, 0x01, 0x02, 0x03, 0x03, 0x04, 0x05 }, out.split().former.buf);
}

test "decode ApplicationLayerProtocolNegotiation" {
    var buf = [_]u8{ 0x00, 0x07, 0x02, 0x01, 0x02, 0x03, 0x03, 0x04, 0x05 };
    var in = Bytes{ .buf = &buf };

    const got = try ApplicationLayerProtocolNegotiation.decode(std.testing.allocator, &in);
    defer got.deinit();

    const names = got.protocol_name_list.data.items;
    try std.testing.expectEqual(@as(usize, 2), names.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, names[0].data.items);
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0x04, 0x05 }, names[1].data.items);
}
