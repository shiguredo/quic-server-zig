const std = @import("std");
const mem = std.mem;
const math = std.math;
const Allocator = mem.Allocator;
const PriorityQueue = std.PriorityQueue;
const Deque = @import("./deque.zig").Deque;

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
        const data = try allocator.dupe(u8, buf);

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

fn rangeBufCompare(context: void, a: RangeBuf, b: RangeBuf) math.Order {
    _ = context;
    return math.order(a.offset, b.offset);
}

pub const RecvBuf = struct {
    /// Chunks of data received from the peer that have not yet been read by
    /// the application, ordered by offset.
    data: RangeBufMinHeap,
    /// The total length of data received on this stream.
    length: usize,

    const RangeBufMinHeap = PriorityQueue(RangeBuf, void, rangeBufCompare);
    const Self = @This();
};

pub const SendBuf = struct {
    /// Chunks of data to be sent to the peer.
    data: SendQueue,
    /// The amount of data currently buffered.
    length: usize,

    const SendQueue = Deque(RangeBuf);
    const Self = @This();
};

pub const Stream = struct {
    /// Receive-side stream buffer.
    recv: RecvBuf,
    /// Send-side stream buffer.
    send: SendBuf,
    /// Whether the stream is bidirectional.
    bidi: bool,
    /// Whether the stream was created by the local endpoint.
    local: bool,
};
