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
        // TODO(magurotuna)
        _ = allocator;
        _ = scid;
        _ = dcid;
        _ = local;
        _ = peer;
        return error.Unimplemented;
    }

    pub fn new(allocator: Allocator, scid: []const u8, dcid: []const u8) !Self {
        var scid_owned = try ArrayList(u8).initCapacity(allocator, scid.len);
        errdefer scid_owned.deinit();
        scid_owned.appendSliceAssumeCapacity(scid);

        var dcid_owned = try ArrayList(u8).initCapacity(allocator, dcid.len);
        errdefer dcid_owned.deinit();
        dcid_owned.appendSliceAssumeCapacity(dcid);

        return Self{
            .scid = scid_owned,
            .dcid = dcid_owned,
            .pkt_num_spaces = PacketNumberSpaces.initFill(.{}),
        };
    }

    pub fn deinit(self: Self) void {
        self.source_connection_id.deinit();
        self.destination_connection_id.deinit();
    }

    pub fn doHandshake(self: *Self) void {
        // TODO
        _ = self;
    }
};
