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
    len: usize,
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
            .len = data.len,
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

    pub fn init(allocator: Allocator) Self {
        return Self{
            .data = RangeBufMinHeap.init(allocator, {}),
            .length = 0,
        };
    }

    pub fn deinit(self: Self) void {
        self.data.deinit();
    }

    pub fn write(self: *Self, buf: RangeBuf) Allocator.Error!void {
        // TODO(magurotuna): there are lots of things to be checked to perform this operation properly.
        // But we just skip that for the moment.
        try self.data.add(buf);
    }

    pub fn emit(self: *Self, out: []u8) !usize {
        if (!self.ready())
            return error.NothingToProcess;

        var n_emit: usize = 0;

        while (n_emit < out.len) {
            const buf = self.data.peek() orelse break;
            const rest = out.len - n_emit;

            // The buffer does not fit into the remaining capacity of `out`; exit from the loop.
            if (buf.len > rest)
                break;

            mem.copy(u8, out[n_emit..(n_emit + buf.len)], buf.data);
            n_emit += buf.len;
            _ = self.data.remove();
        }

        return n_emit;
    }

    /// Returns true if the stream has data to be read.
    pub fn ready(self: Self) bool {
        return self.data.count() > 0;
    }
};

pub const SendBuf = struct {
    /// Chunks of data to be sent to the peer.
    data: SendQueue,
    /// The amount of data currently buffered.
    length: usize,

    const SendQueue = Deque(RangeBuf);
    const Self = @This();

    pub fn init(allocator: Allocator) Allocator.Error!Self {
        return Self{
            .data = try SendQueue.init(allocator),
            .length = 0,
        };
    }

    pub fn deinit(self: Self) void {
        self.data.deinit();
    }
};

/// Represent the QUIC's stream.
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-streams
pub const Stream = struct {
    /// Receive-side stream buffer.
    recv: RecvBuf,
    /// Send-side stream buffer.
    send: SendBuf,
    /// Whether the stream is bidirectional.
    bidi: bool,
    /// Whether the stream was created by the local endpoint.
    local: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, bidi: bool, local: bool) Allocator.Error!Self {
        const recv = RecvBuf.init(allocator);
        errdefer recv.deinit();
        const send = try SendBuf.init(allocator);
        errdefer send.deinit();

        return Self{
            .recv = recv,
            .send = send,
            .bidi = bidi,
            .local = local,
        };
    }

    pub fn deinit(self: Self) void {
        self.recv.deinit();
        self.send.deinit();
    }
};
