const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const PacketNumberSpaces = @import("./packet_number_space.zig").PacketNumberSpaces;

pub const Conn = struct {
    scid: ArrayList(u8),
    dcid: ArrayList(u8),
    pkt_num_spaces: PacketNumberSpaces,

    const Self = @This();

    pub fn accept(
        allocator: Allocator,
        scid: []const u8,
        dcid: []const u8,
        local: net.Address,
        peer: net.Address,
    ) !Self {
        // TODO(magurotuna): use these values probably for path verification
        _ = local;
        _ = peer;

        var scid_owned = try ArrayList(u8).initCapacity(allocator, scid.len);
        errdefer scid_owned.deinit();
        scid_owned.appendSliceAssumeCapacity(scid);

        var dcid_owned = try ArrayList(u8).initCapacity(allocator, dcid.len);
        errdefer dcid_owned.deinit();
        dcid_owned.appendSliceAssumeCapacity(dcid);

        // Initialize three packet number spaces.
        var pkt_num_spaces = PacketNumberSpaces.init(allocator);
        errdefer pkt_num_spaces.deinit();
        // For the Initial space, we can derive data needed to encrypt/decrypt right away.
        try pkt_num_spaces.setInitialCryptor(allocator, dcid, true);

        return Self{
            .scid = scid_owned,
            .dcid = dcid_owned,
            .pkt_num_spaces = pkt_num_spaces,
        };
    }

    pub fn deinit(self: Self) void {
        self.source_connection_id.deinit();
        self.destination_connection_id.deinit();
    }

    pub fn recv(self: *Self, buf: []u8, local: net.Address, peer: net.Address) !usize {
        // TODO(maguorotuna)
        _ = self;
        _ = buf;
        _ = local;
        _ = peer;
        return error.Unimplemented;
    }
};
