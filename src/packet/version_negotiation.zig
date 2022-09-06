const std = @import("std");
const Bytes = @import("../bytes.zig").Bytes;

// TODO(magurotuna)
pub const VersionNegotiation = struct {
    const Self = @This();

    pub fn encode(self: Self, out: *Bytes) !void {
        // TODO(magurotuna)
        _ = self;
        _ = out;
    }
};
