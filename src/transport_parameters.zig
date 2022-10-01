//! Transport parameters
//!
//! https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameters
//! https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-encodin
//! https://www.rfc-editor.org/rfc/rfc9001.html#name-quic-transport-parameters-e

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

original_destination_connection_id: ?ArrayList(u8),
max_idle_timeout: u64,
stateless_reset_token: ?[16]u8,
max_udp_payload_size: u64,
initial_max_data: u64,
initial_max_stream_data_bidi_local: u64,
initial_max_stream_data_bidi_remote: u64,
initial_max_stream_data_uni: u64,
initial_max_streams_bidi: u64,
initial_max_streams_uni: u64,
ack_delay_exponent: u64,
max_ack_delay: u64,
disable_active_migration: bool,
active_conn_id_limit: u64,
initial_source_connection_id: ?ArrayList(u8),
retry_source_connection_id: ?ArrayList(u8),

const Self = @This();

/// Return the QUIC transport parameters with the default values set.
///
/// The default values and what each field means are defined in the RFC:
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
pub fn default() Self {
    return .{
        .original_destination_connection_id = null,
        .max_idle_timeout = 0,
        .stateless_reset_token = null,
        .max_udp_payload_size = 65527,
        .initial_max_data = 0,
        .initial_max_stream_data_bidi_local = 0,
        .initial_max_stream_data_bidi_remote = 0,
        .initial_max_stream_data_uni = 0,
        .initial_max_streams_bidi = 0,
        .initial_max_streams_uni = 0,
        .ack_delay_exponent = 3,
        .max_ack_delay = 25,
        .disable_active_migration = false,
        .active_conn_id_limit = 2,
        .initial_source_connection_id = null,
        .retry_source_connection_id = null,
    };
}

pub fn deinit(self: Self) void {
    if (self.original_destination_connection_id) |x| x.deinit();
    if (self.initial_source_connection_id) |x| x.deinit();
    if (self.retry_source_connection_id) |x| x.deinit();
}

pub fn clone(self: Self, allocator: Allocator) Allocator.Error!Self {
    var odcid: ?ArrayList(u8) = null;
    if (self.original_destination_connection_id) |x| {
        var id = try ArrayList(u8).initCapacity(allocator, x.items.len);
        id.appendSliceAssumeCapacity(x.items);
        odcid = id;
    }
    errdefer if (odcid) |x| x.deinit();

    var iscid: ?ArrayList(u8) = null;
    if (self.initial_source_connection_id) |x| {
        var id = try ArrayList(u8).initCapacity(allocator, x.items.len);
        id.appendSliceAssumeCapacity(x.items);
        iscid = id;
    }
    errdefer if (iscid) |x| x.deinit();

    var rscid: ?ArrayList(u8) = null;
    if (self.retry_source_connection_id) |x| {
        var id = try ArrayList(u8).initCapacity(allocator, x.items.len);
        id.appendSliceAssumeCapacity(x.items);
        rscid = id;
    }
    errdefer if (rscid) |x| x.deinit();

    var token: ?[16]u8 = null;
    if (self.stateless_reset_token) |x| {
        var d: [16]u8 = undefined;
        mem.copy(u8, &d, &x);
        token = d;
    }

    return Self{
        .original_destination_connection_id = odcid,
        .max_idle_timeout = self.max_idle_timeout,
        .stateless_reset_token = token,
        .max_udp_payload_size = self.max_udp_payload_size,
        .initial_max_data = self.initial_max_data,
        .initial_max_stream_data_bidi_local = self.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote = self.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = self.initial_max_stream_data_uni,
        .initial_max_streams_bidi = self.initial_max_streams_bidi,
        .initial_max_streams_uni = self.initial_max_streams_uni,
        .ack_delay_exponent = self.ack_delay_exponent,
        .max_ack_delay = self.max_ack_delay,
        .disable_active_migration = self.disable_active_migration,
        .active_conn_id_limit = self.active_conn_id_limit,
        .initial_source_connection_id = iscid,
        .retry_source_connection_id = rscid,
    };
}
