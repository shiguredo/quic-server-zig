const std = @import("std");
const Bytes = @import("../../bytes.zig").Bytes;
const ArrayList = std.ArrayList;

/// [RFC 8447]
/// https://datatracker.ietf.org/doc/html/rfc8447#section-6
///
/// > IANA has renamed entry 35 to "session_ticket (renamed from "SessionTicket TLS")" [RFC5077].
///
/// [RFC 5077]
/// https://datatracker.ietf.org/doc/html/rfc5077#section-3.2
///
/// > The format of the ticket is an opaque structure used to carry session-specific state information.
///
/// > The SessionTicket extension has been assigned the number 35.  The
/// > extension_data field of SessionTicket extension contains the ticket.
///
/// [NOTE]
/// Contains opaque data only. Unlike other extensions such as `RenegotiationInfo`,
/// this type does not manege the length of the data; you can basically think of this
/// type as variable-length vector WITHOUT the management of length. Encoding and
/// decoding the data length is out of this type's responsibility. The length should
/// be managed in `Extension` type instead.
pub const SessionTicket = struct {
    ticket: ArrayList(u8),

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.ticket.items.len;
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.putBytes(self.ticket.items);
    }

    /// Note that callers must ensure that `in` is filled with ticket data only,
    /// because the management of length is callers' responsibility.
    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        return Self{
            .ticket = try in.consumeBytesUntilEndOwned(allocator),
        };
    }

    pub fn deinit(self: Self) void {
        self.ticket.deinit();
    }
};

test "encode SessionTicket" {
    const ticket = SessionTicket{
        .ticket = blk: {
            var t = ArrayList(u8).init(std.testing.allocator);
            try t.appendSlice(&.{ 0x00, 0x01 });
            break :blk t;
        },
    };
    defer ticket.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ticket.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, out.split().former.buf);
}

test "encode empty SessionTicket" {
    const ticket = SessionTicket{
        .ticket = ArrayList(u8).init(std.testing.allocator),
    };
    defer ticket.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ticket.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{}, out.split().former.buf);
}

test "decode SessionTicket" {
    var buf = [_]u8{ 0x00, 0x01 };
    var in = Bytes{ .buf = &buf };

    const got = try SessionTicket.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, got.ticket.items);
}

test "decode empty SessionTicket" {
    var buf = [_]u8{};
    var in = Bytes{ .buf = &buf };

    const got = try SessionTicket.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqualSlices(u8, &.{}, got.ticket.items);
}
