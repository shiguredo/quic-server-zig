const std = @import("std");
const mem = std.mem;
const meta = std.meta;
const ArrayList = std.ArrayList;
const BoundedArray = std.BoundedArray;
const bytes = @import("../../bytes.zig");

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-encodin
///
/// Transport Parameters {
///   Transport Parameter (..) ...,
/// }
pub const TransportParameters = struct {
    parameters: ArrayList(TransportParameter),

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        var len: usize = 0;
        for (self.parameters.items) |p| {
            len += p.encodedLength();
        }
        return len;
    }

    pub fn encode(self: Self, out: *bytes.Bytes) !void {
        for (self.parameters.items) |p| {
            try p.encode(out);
        }
    }

    /// Callers must guarantee that the input buffer `in` contains quic_transport_parameters only.
    pub fn decode(allocator: std.mem.Allocator, in: *bytes.Bytes) !Self {
        var params = ArrayList(TransportParameter).init(allocator);
        errdefer params.deinit();

        decode_params: while (true) {
            const p = TransportParameter.decode(allocator, in) catch |e| {
                // In case of `BufferTooShort` it indicates all parameters have been decoded.
                if (e == bytes.Bytes.Error.BufferTooShort) {
                    break :decode_params;
                }
                return e;
            };
            errdefer p.deinit();
            try params.append(p);
        }

        return Self{ .parameters = params };
    }

    pub fn deinit(self: Self) void {
        for (self.parameters.items) |p| {
            p.deinit();
        }
        self.parameters.deinit();
    }
};

test "encode TransportParameters" {
    const transport_parameters = TransportParameters{
        .parameters = blk: {
            var ps = ArrayList(TransportParameter).init(std.testing.allocator);
            errdefer ps.deinit();
            try ps.appendSlice(&.{
                .{ .max_idle_timeout = 0x09 },
                .{ .stateless_reset_token = .{0x42} ** 16 },
                .{ .disable_active_migration = {} },
            });
            break :blk ps;
        },
    };
    defer transport_parameters.deinit();

    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try transport_parameters.encode(&out);

    const timeout = [_]u8{ 0x01, 0x01, 0x09 };
    const tok = [_]u8{ 0x02, 0x10 } ++ [_]u8{0x42} ** 16;
    const disable_active_migration = [_]u8{ 0x0c, 0x00 };
    try std.testing.expectEqualSlices(u8, &(timeout ++ tok ++ disable_active_migration), out.split().former.buf);
}

test "decode TransportParameters" {
    const timeout = [_]u8{ 0x01, 0x01, 0x09 };
    const tok = [_]u8{ 0x02, 0x10 } ++ [_]u8{0x42} ** 16;
    const disable_active_migration = [_]u8{ 0x0c, 0x00 };
    var buf = timeout ++ tok ++ disable_active_migration;
    var in = bytes.Bytes{ .buf = &buf };

    const got = try TransportParameters.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(usize, 3), got.parameters.items.len);
    try std.testing.expectEqualSlices(
        TransportParameter,
        &.{
            .{ .max_idle_timeout = 0x09 },
            .{ .stateless_reset_token = .{0x42} ** 16 },
            .{ .disable_active_migration = {} },
        },
        got.parameters.items,
    );
}

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-encodin
///
/// Transport Parameter {
///   Transport Parameter ID (i),
///   Transport Parameter Length (i),
///   Transport Parameter Value (..),
/// }
///
/// > Transport parameters have a default value of 0 if the transport parameter is absent,
/// > unless otherwise stated.
pub const TransportParameter = union(TransportParameterId) {
    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > This parameter is the value of the Destination Connection ID field from the first
    /// > Initial packet sent by the client.
    ///
    /// [Authenticating Connection IDs]: https://www.rfc-editor.org/rfc/rfc9000.html#name-authenticating-connection-i
    original_destination_connection_id: ArrayList(u8),

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > The maximum idle timeout is a value in milliseconds that is encoded as an integer.
    ///
    /// [Idle Timeout]: https://www.rfc-editor.org/rfc/rfc9000.html#idle-timeout
    max_idle_timeout: u64,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > A stateless reset token is used in verifying a stateless reset.
    ///
    /// > This parameter is a sequence of 16 bytes.
    ///
    /// [Stateless Reset]: https://www.rfc-editor.org/rfc/rfc9000.html#stateless-reset
    stateless_reset_token: [16]u8,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > The maximum UDP payload size parameter is an integer value that limits the size of
    /// > UDP payloads that the endpoint is willing to receive. UDP datagrams with payloads larger
    /// > than this limit are not likely to be processed by the receiver.
    ///
    /// > The default for this parameter is the maximum permitted UDP payload of 65527.
    /// > Values below 1200 are invalid.
    max_udp_payload_size: u64,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > The initial maximum data parameter is an integer value that contains the initial value
    /// > for the maximum amount of data that can be sent on the connection.
    initial_max_data: u64,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > This parameter is an integer value specifying the initial flow control limit for
    /// > locally initiated bidirectional streams
    initial_max_stream_data_bidi_local: u64,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > This parameter is an integer value specifying the initial flow control limit for
    /// > peer-initiated bidirectional streams.
    initial_max_stream_data_bidi_remote: u64,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > This parameter is an integer value specifying the initial flow control limit for
    /// > unidirectional streams.
    initial_max_stream_data_uni: u64,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > The initial maximum bidirectional streams parameter is an integer value that contains
    /// > the initial maximum number of bidirectional streams the endpoint that receives this
    /// > transport parameter is permitted to initiate. If this parameter is absent or zero,
    /// > the peer cannot open bidirectional streams until a MAX_STREAMS frame is sent.
    initial_max_streams_bidi: u64,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > The initial maximum unidirectional streams parameter is an integer value that contains
    /// > the initial maximum number of unidirectional streams the endpoint that receives this
    /// > transport parameter is permitted to initiate. If this parameter is absent or zero,
    /// > the peer cannot open unidirectional streams until a MAX_STREAMS frame is sent.
    initial_max_streams_uni: u64,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > The acknowledgment delay exponent is an integer value indicating an exponent used to
    /// > decode the ACK Delay field in the ACK frame (Section 19.3). If this value is absent,
    /// > a default value of 3 is assumed (indicating a multiplier of 8). Values above 20 are invalid.
    ack_delay_exponent: u64,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > The maximum acknowledgment delay is an integer value indicating the maximum amount of
    /// > time in milliseconds by which the endpoint will delay sending acknowledgments.
    ///
    /// > If this value is absent, a default of 25 milliseconds is assumed. Values of 214 or
    /// > greater are invalid.
    max_ack_delay: u64,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > The disable active migration transport parameter is included if the endpoint does not
    /// > support active connection migration on the address being used during the handshake. 
    /// 
    /// [Conenction Migration]: https://www.rfc-editor.org/rfc/rfc9000.html#migration
    ///
    /// >  This parameter is a zero-length value.
    disable_active_migration: void,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > The server's preferred address is used to effect a change in server address at the
    /// > end of the handshake.
    ///
    /// [Server's Preferred Address]: https://www.rfc-editor.org/rfc/rfc9000.html#name-servers-preferred-address
    ///
    /// Preferred Address {
    ///   IPv4 Address (32),
    ///   IPv4 Port (16),
    ///   IPv6 Address (128),
    ///   IPv6 Port (16),
    ///   Connection ID Length (8),
    ///   Connection ID (..),
    ///   Stateless Reset Token (128),
    /// }
    preferred_address: PreferredAddress,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > This is an integer value specifying the maximum number of connection IDs from the
    /// > peer that an endpoint is willing to store.
    ///
    /// > The value of the active_connection_id_limit parameter MUST be at least 2.
    ///
    /// > If this transport parameter is absent, a default of 2 is assumed.
    active_connection_id_limit: u64,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > This is the value that the endpoint included in the Source Connection ID field of
    /// > the first Initial packet it sends for the connection.
    ///
    /// [Authenticating Conneciton IDs]: https://www.rfc-editor.org/rfc/rfc9000.html#name-authenticating-connection-i
    initial_source_connection_id: ArrayList(u8),

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
    ///
    /// > This is the value that the server included in the Source Connection ID field of
    /// > a Retry packet.
    ///
    /// [Authenticating Conneciton IDs]: https://www.rfc-editor.org/rfc/rfc9000.html#name-authenticating-connection-i
    retry_source_connection_id: ArrayList(u8),

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        const id_len = bytes.varIntLength(@enumToInt(self));
        const value_len = self.valueLength();
        const param_len = bytes.varIntLength(value_len);

        return id_len + param_len + value_len;
    }

    fn valueLength(self: Self) usize {
        return switch (self) {
            .max_idle_timeout,
            .max_udp_payload_size,
            .initial_max_data,
            .initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni,
            .initial_max_streams_bidi,
            .initial_max_streams_uni,
            .ack_delay_exponent,
            .max_ack_delay,
            .active_connection_id_limit,
            => |a| bytes.varIntLength(a),

            .original_destination_connection_id,
            .initial_source_connection_id,
            .retry_source_connection_id,
            => |a| a.items.len,

            .stateless_reset_token => 16,
            .disable_active_migration => 0,

            .preferred_address => |a| a.encodedLength(),
        };
    }

    pub fn encode(self: Self, out: *bytes.Bytes) !void {
        try out.putVarInt(@enumToInt(self));
        try out.putVarInt(@intCast(u64, self.valueLength()));

        switch (self) {
            .max_idle_timeout,
            .max_udp_payload_size,
            .initial_max_data,
            .initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni,
            .initial_max_streams_bidi,
            .initial_max_streams_uni,
            .ack_delay_exponent,
            .max_ack_delay,
            .active_connection_id_limit,
            => |a| try out.putVarInt(a),

            .original_destination_connection_id,
            .initial_source_connection_id,
            .retry_source_connection_id,
            => |a| try out.putBytes(a.items),

            .stateless_reset_token => |a| try out.putBytes(&a),
            .disable_active_migration => {},

            .preferred_address => |a| try a.encode(out),
        }
    }

    pub fn decode(allocator: std.mem.Allocator, in: *bytes.Bytes) !Self {
        const id = try in.consumeVarInt();
        const length = try in.consumeVarInt();
        var param_value_bytes = bytes.Bytes{ .buf = try in.consumeBytes(length) };

        // We ignore the value if parameter_id is unknown to us.
        const ty = try meta.intToEnum(TransportParameterId, id);

        return switch (ty) {
            .max_idle_timeout => .{
                .max_idle_timeout = try param_value_bytes.consumeVarInt(),
            },
            .max_udp_payload_size => .{
                .max_udp_payload_size = try param_value_bytes.consumeVarInt(),
            },
            .initial_max_data => .{
                .initial_max_data = try param_value_bytes.consumeVarInt(),
            },
            .initial_max_stream_data_bidi_local => .{
                .initial_max_stream_data_bidi_local = try param_value_bytes.consumeVarInt(),
            },
            .initial_max_stream_data_bidi_remote => .{
                .initial_max_stream_data_bidi_remote = try param_value_bytes.consumeVarInt(),
            },
            .initial_max_stream_data_uni => .{
                .initial_max_stream_data_uni = try param_value_bytes.consumeVarInt(),
            },
            .initial_max_streams_bidi => .{
                .initial_max_streams_bidi = try param_value_bytes.consumeVarInt(),
            },
            .initial_max_streams_uni => .{
                .initial_max_streams_uni = try param_value_bytes.consumeVarInt(),
            },
            .ack_delay_exponent => .{
                .ack_delay_exponent = try param_value_bytes.consumeVarInt(),
            },
            .max_ack_delay => .{
                .max_ack_delay = try param_value_bytes.consumeVarInt(),
            },
            .active_connection_id_limit => .{
                .active_connection_id_limit = try param_value_bytes.consumeVarInt(),
            },

            .original_destination_connection_id => .{
                .original_destination_connection_id = try param_value_bytes.consumeBytesUntilEndOwned(allocator),
            },
            .initial_source_connection_id => .{
                .initial_source_connection_id = try param_value_bytes.consumeBytesUntilEndOwned(allocator),
            },
            .retry_source_connection_id => .{
                .retry_source_connection_id = try param_value_bytes.consumeBytesUntilEndOwned(allocator),
            },

            .stateless_reset_token => .{
                .stateless_reset_token = blk: {
                    var tok: [16]u8 = undefined;
                    mem.copy(u8, &tok, try param_value_bytes.consumeBytesUntilEnd());
                    break :blk tok;
                },
            },
            .disable_active_migration => .{ .disable_active_migration = {} },

            .preferred_address => .{
                .preferred_address = try PreferredAddress.decode(allocator, &param_value_bytes),
            },
        };
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            .max_idle_timeout,
            .max_udp_payload_size,
            .initial_max_data,
            .initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni,
            .initial_max_streams_bidi,
            .initial_max_streams_uni,
            .ack_delay_exponent,
            .max_ack_delay,
            .active_connection_id_limit,

            .stateless_reset_token,
            .disable_active_migration,
            => {},

            .original_destination_connection_id,
            .initial_source_connection_id,
            .retry_source_connection_id,
            => |a| a.deinit(),

            .preferred_address => |a| a.deinit(),
        }
    }
};

test "encode TransportParameter (original_destination_connection_id)" {
    const param = TransportParameter{
        .original_destination_connection_id = blk: {
            var id = ArrayList(u8).init(std.testing.allocator);
            errdefer id.deinit();
            try id.appendSlice(&.{ 0x01, 0x02 });
            break :blk id;
        },
    };
    defer param.deinit();

    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try param.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x02, 0x01, 0x02 }, out.split().former.buf);
}

test "decode TransportParameter (original_destination_connection_id)" {
    var buf = [_]u8{ 0x00, 0x02, 0x01, 0x02 };
    var in = bytes.Bytes{ .buf = &buf };

    const got = try TransportParameter.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, got.original_destination_connection_id.items);
}

test "encode TransportParameter (max_idle_timeout)" {
    const param = TransportParameter{
        .max_idle_timeout = 0x09,
    };
    defer param.deinit();

    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try param.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x01, 0x09 }, out.split().former.buf);
}

test "decode TransportParameter (max_idle_timeout)" {
    var buf = [_]u8{ 0x01, 0x01, 0x09 };
    var in = bytes.Bytes{ .buf = &buf };

    const got = try TransportParameter.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(u64, 9), got.max_idle_timeout);
}

test "encode TransportParameter (stateless_reset_token)" {
    const param = TransportParameter{
        .stateless_reset_token = .{0x42} ** 16,
    };
    defer param.deinit();

    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try param.encode(&out);

    try std.testing.expectEqualSlices(
        u8,
        &(.{ 0x02, 0x10 } ++ .{0x42} ** 16),
        out.split().former.buf,
    );
}

test "decode TransportParameter (stateless_reset_token)" {
    var buf = [_]u8{ 0x02, 0x10 } ++ [_]u8{0x42} ** 16;
    var in = bytes.Bytes{ .buf = &buf };

    const got = try TransportParameter.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqualSlices(u8, &(.{0x42} ** 16), &got.stateless_reset_token);
}

test "encode TransportParameter (disable_active_migration)" {
    const param = TransportParameter{
        .disable_active_migration = {},
    };
    defer param.deinit();

    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try param.encode(&out);

    try std.testing.expectEqualSlices(u8, &.{ 0x0c, 0x00 }, out.split().former.buf);
}

test "decode TransportParameter (disable_active_migration)" {
    var buf = [_]u8{ 0x0c, 0x00 };
    var in = bytes.Bytes{ .buf = &buf };

    const got = try TransportParameter.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(TransportParameterId.disable_active_migration, got);
}

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
pub const TransportParameterId = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-reserved-transport-paramete
    //
    // > Transport parameters with an identifier of the form 31 * N + 27 for integer values of N
    // > are reserved to exercise the requirement that unknown transport parameters be ignored.
    // > These transport parameters have no semantics and can carry arbitrary values.

    const Self = @This();
    const TagType = @typeInfo(Self).Enum.tag_type;
};

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
///
/// Preferred Address {
///   IPv4 Address (32),
///   IPv4 Port (16),
///   IPv6 Address (128),
///   IPv6 Port (16),
///   Connection ID Length (8),
///   Connection ID (..),
///   Stateless Reset Token (128),
/// }
pub const PreferredAddress = struct {
    ipv4_addr: [4]u8,
    ipv4_port: u16,
    ipv6_addr: [16]u8,
    ipv6_port: u16,
    connection_id: ConnectionId,
    stateless_reset_token: [16]u8,

    const Self = @This();
    /// `Connection ID Length` is a 8-bit integer, so it must be less than or equal to 255.
    const ConnectionId = BoundedArray(u8, 255);

    pub fn encodedLength(self: Self) usize {
        return @sizeOf([4]u8) + @sizeOf(u16) + @sizeOf([16]u8) + @sizeOf(u16) + self.connection_id.len + @sizeOf([16]u8);
    }

    pub fn encode(self: Self, out: *bytes.Bytes) !void {
        try out.putBytes(&self.ipv4_addr);
        try out.put(u16, self.ipv4_port);
        try out.putBytes(&self.ipv6_addr);
        try out.put(u16, self.ipv6_port);
        try out.put(u8, @intCast(u8, self.connection_id.len));
        try out.putBytes(self.connection_id.constSlice());
        try out.putBytes(&self.stateless_reset_token);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *bytes.Bytes) !Self {
        _ = allocator;

        var ret: Self = undefined;

        mem.copy(u8, &ret.ipv4_addr, try in.consumeBytes(4));
        ret.ipv4_port = try in.consume(u16);
        mem.copy(u8, &ret.ipv6_addr, try in.consumeBytes(16));
        ret.ipv6_port = try in.consume(u16);

        const connection_id_length = try in.consume(u8);
        const connection_id = try in.consumeBytes(@intCast(usize, connection_id_length));
        ret.connection_id = try ConnectionId.fromSlice(connection_id);

        mem.copy(u8, &ret.stateless_reset_token, try in.consumeBytes(16));

        return ret;
    }

    pub fn deinit(self: Self) void {
        // no-op
        _ = self;
    }
};

test "encode PreferredAddress" {
    const addr = PreferredAddress{
        .ipv4_addr = .{0x04} ** 4,
        .ipv4_port = 4444,
        .ipv6_addr = .{0x06} ** 16,
        .ipv6_port = 6666,
        .connection_id = try PreferredAddress.ConnectionId.fromSlice(&.{ 0x01, 0x02, 0x03 }),
        .stateless_reset_token = .{0x09} ** 16,
    };
    defer addr.deinit();

    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try addr.encode(&out);

    // zig fmt: off
    try std.testing.expectEqualSlices(u8, &.{
        // v4
        0x04, 0x04, 0x04, 0x04, 0x11, 0x5c,
        // v6
        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x1a, 0x0a,
        // connection_id
        0x03, 0x01, 0x02, 0x03,
        // stateless_reset_token
        0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
        0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    }, out.split().former.buf);
    // zig fmt: on
}

test "decode PreferredAddress" {
    // zig fmt: off
    var buf = [_]u8{
        // v4
        0x04, 0x04, 0x04, 0x04, 0x11, 0x5c,
        // v6
        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x1a, 0x0a,
        // connection_id
        0x03, 0x01, 0x02, 0x03,
        // stateless_reset_token
        0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
        0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    };
    // zig fmt: on
    var in = bytes.Bytes{ .buf = &buf };

    const got = try PreferredAddress.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqualSlices(u8, &(.{0x04} ** 4), &got.ipv4_addr);
    try std.testing.expectEqual(@as(u16, 4444), got.ipv4_port);
    try std.testing.expectEqualSlices(u8, &(.{0x06} ** 16), &got.ipv6_addr);
    try std.testing.expectEqual(@as(u16, 6666), got.ipv6_port);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, got.connection_id.constSlice());
    try std.testing.expectEqualSlices(u8, &(.{0x09} ** 16), &got.stateless_reset_token);
}
