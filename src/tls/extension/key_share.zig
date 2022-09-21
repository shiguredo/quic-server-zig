const std = @import("std");
const VariableLengthVector = @import("../../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../../bytes.zig").Bytes;
const supported_groups = @import("./supported_groups.zig");

pub const ClientShares = VariableLengthVector(KeyShareEntry, 65535);
pub const KeyExchange = VariableLengthVector(u8, 65535);

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8
///
/// > In the ClientHello message, the "extension_data" field of this extension
/// > contains a "KeyShareClientHello" value:
///
/// struct {
///     KeyShareEntry client_shares<0..2^16-1>;
/// } KeyShareClientHello;
pub const KeyShareClientHello = struct {
    client_shares: ClientShares,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.client_shares.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.client_shares.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        return Self{
            .client_shares = try ClientShares.decode(allocator, in),
        };
    }

    pub fn deinit(self: Self) void {
        self.client_shares.deinit();
    }
};

test "encode KeyShareClientHello" {
    const ks = KeyShareClientHello{
        .client_shares = try ClientShares.fromSlice(std.testing.allocator, &.{
            .{
                .group = .x25519,
                .key_exchange = try KeyExchange.fromSlice(std.testing.allocator, &.{ 0x01, 0x02 }),
            },
            .{
                .group = .ffdhe2048,
                .key_exchange = try KeyExchange.fromSlice(std.testing.allocator, &.{0x03}),
            },
        }),
    };
    defer ks.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ks.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x0b, 0x00, 0x1d, 0x00, 0x02, 0x01, 0x02, 0x01, 0x00, 0x00, 0x01, 0x03,
    }, out.split().former.buf);
}

test "decode KeyShareClientHello" {
    var buf = [_]u8{
        0x00, 0x0b, 0x00, 0x1d, 0x00, 0x02, 0x01, 0x02, 0x01, 0x00, 0x00, 0x01, 0x03,
    };
    var in = Bytes{ .buf = &buf };

    const got = try KeyShareClientHello.decode(std.testing.allocator, &in);
    defer got.deinit();

    const shares = got.client_shares.data.items;
    try std.testing.expectEqual(@as(usize, 2), shares.len);
    try std.testing.expectEqual(supported_groups.NamedGroup.x25519, shares[0].group);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, shares[0].key_exchange.data.items);
    try std.testing.expectEqual(supported_groups.NamedGroup.ffdhe2048, shares[1].group);
    try std.testing.expectEqualSlices(u8, &.{0x03}, shares[1].key_exchange.data.items);
}

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8
///
/// > In a ServerHello message, the "extension_data" field of this
/// > extension contains a KeyShareServerHello value:
///
/// struct {
///     KeyShareEntry server_share;
/// } KeyShareServerHello;
pub const KeyShareServerHello = struct {
    server_share: KeyShareEntry,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.server_share.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.server_share.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        return Self{
            .server_share = try KeyShareEntry.decode(allocator, in),
        };
    }

    pub fn deinit(self: Self) void {
        self.server_share.deinit();
    }
};

test "encode KeyShareServerHello" {
    const ks = KeyShareServerHello{
        .server_share = .{
            .group = .x25519,
            .key_exchange = try KeyExchange.fromSlice(std.testing.allocator, &.{ 0x01, 0x02 }),
        },
    };
    defer ks.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ks.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x1d, 0x00, 0x02, 0x01, 0x02 }, out.split().former.buf);
}

test "decode KeyShareServerHello" {
    var buf = [_]u8{ 0x00, 0x1d, 0x00, 0x02, 0x01, 0x02 };
    var in = Bytes{ .buf = &buf };

    const got = try KeyShareServerHello.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(supported_groups.NamedGroup.x25519, got.server_share.group);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, got.server_share.key_exchange.data.items);
}

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8
///
/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
pub const KeyShareEntry = struct {
    group: supported_groups.NamedGroup,
    key_exchange: KeyExchange,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return self.group.encodedLength() + self.key_exchange.encodedLength();
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try self.group.encode(out);
        try self.key_exchange.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        const group = try supported_groups.NamedGroup.decode(allocator, in);
        errdefer group.deinit();
        const key_exchange = try KeyExchange.decode(allocator, in);
        errdefer key_exchange.deinit();

        return Self{
            .group = group,
            .key_exchange = key_exchange,
        };
    }

    pub fn deinit(self: Self) void {
        self.group.deinit();
        self.key_exchange.deinit();
    }
};

test "encode KeyShareEntry" {
    const ent = KeyShareEntry{
        .group = .x25519,
        .key_exchange = try KeyExchange.fromSlice(std.testing.allocator, &.{ 0x01, 0x02 }),
    };
    defer ent.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ent.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x1d, 0x00, 0x02, 0x01, 0x02 }, out.split().former.buf);
}

test "decode KeyShareEntry" {
    var buf = [_]u8{ 0x00, 0x1d, 0x00, 0x02, 0x01, 0x02 };
    var in = Bytes{ .buf = &buf };

    const got = try KeyShareEntry.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(supported_groups.NamedGroup.x25519, got.group);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, got.key_exchange.data.items);
}

/// Pick up a key share entry with the supported named group, if any, from the given set of entries.
/// When there are multiple entries included in the set, one that appears first in the set will be chosen.
/// If there's no supported entries this returns `null`.
pub fn pickKeyShareEntry(entries: []const KeyShareEntry) ?KeyShareEntry {
    for (entries) |e| {
        if (supported_groups.supported_named_groups.contains(e.group))
            return e;
    }
    return null;
}
