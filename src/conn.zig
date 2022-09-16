const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const PacketNumberSpaces = @import("./packet_number_space.zig").PacketNumberSpaces;
const Bytes = @import("./bytes.zig").Bytes;
const packet = @import("./packet.zig");

pub const Conn = struct {
    scid: ArrayList(u8),
    dcid: ArrayList(u8),
    pkt_num_spaces: PacketNumberSpaces,

    allocator: Allocator,

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
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        self.source_connection_id.deinit();
        self.destination_connection_id.deinit();
    }

    pub fn recv(self: *Self, buf: []u8, local: net.Address, peer: net.Address) !usize {
        _ = local;
        _ = peer;

        var done: usize = 0;
        var left: usize = buf.len;

        // One UDP datagram may contain multiple QUIC packets. We handle each packet one by one.
        while (left > 0) {
            const read = try self.recvSingle(buf);
            left -= read;
            done += read;
        }

        return done;
    }

    /// Process just one QUIC packet from the buffer and returns the number of bytes processed.
    fn recvSingle(self: *Self, buf: []u8) !usize {
        var input = Bytes{ .buf = buf };

        const hdr = try packet.Header.fromBytes(self.allocator, &input, self.dcid.items.len);
        defer hdr.deinit();

        if (self.pkt_num_spaces.getByPacketType(hdr.packet_type)) |pkt_num_space| {
            _ = pkt_num_space;
        } else |_| {}

        return error.Unimplemented;
    }
};
