const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// This type represents a split chunk of a QUIC's stream.
pub const RangeBuf = struct {
    /// The buffer holding the data.
    data: []const u8,
    /// Offset of the buffer in the stream.
    offset: usize,
    /// The length of this chunk.
    length: usize,
    /// Whether this buffer contains the final byte of the stream.
    fin: bool,
    /// Allocator used to allocate the internal buffer (`data`).
    allocator: Allocator,

    const Self = @This();

    pub fn from(allocator: Allocator, buf: []const u8, offset: usize, fin: bool) Allocator.Error!Self {
        var data = try allocator.alloc(u8, buf.len);
        mem.copy(u8, data, buf);

        return Self{
            .data = data,
            .offset = offset,
            .length = data.len,
            .fin = fin,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.data);
    }
};
