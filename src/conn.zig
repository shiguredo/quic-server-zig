const std = @import("std");
const net = std.net;
const ArrayList = std.ArrayList;
const Bytes = @import("./bytes.zig").Bytes;
const Initial = @import("./packet/initial.zig").Initial;
const quic_v1 = @import("./version.zig").quic_v1;

pub const Conn = struct {
    source_connection_id: ArrayList(u8),
    destination_connection_id: ArrayList(u8),

    const Self = @This();

    /// Accepts the connection from a client and creates a new `Conn` instance to manage its state.
    pub fn accept(
        allocator: std.mem.Allocator,
        source_connection_id: []const u8,
        original_destination_connection_id: []const u8,
        local: net.Address,
        peer: net.Address,
    ) !Self {
        var scid = try ArrayList(u8).initCapacity(allocator, source_connection_id.len);
        errdefer scid.deinit();
        scid.appendSliceAssumeCapacity(source_connection_id);

        var odcid = try ArrayList(u8).initCapacity(allocator, original_destination_connection_id.len);
        errdefer odcid.deinit();
        odcid.appendSliceAssumeCapacity(original_destination_connection_id);

        // TODO(magurotuna): use local and peer address information
        _ = local;
        _ = peer;

        return Self{
            .source_connection_id = scid,
            .original_destination_connection_id = odcid,
        };
    }

    pub fn deinit(self: Self) void {
        self.source_connection_id.deinit();
        self.destination_connection_id.deinit();
    }

    /// Processes QUIC packets received from the peer, returning the number of bytes processed.
    /// `buf` is expected to be the payload of UDP.
    pub fn recv(self: *Self, buf: []u8) !usize {
        // TODO(magurotuna): `buf` may contain multiple QUIC packets, which referred to as "coalesced",
        // but for now those cases are not handled properly.

        _ = self;
        _ = buf;

        // if (!self.handshake_completed) {
        //     self.do_handshake();
        // }
    }
};
