//! Transport parameters
//!
//! https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameters
//! https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-encodin
//! https://www.rfc-editor.org/rfc/rfc9001.html#name-quic-transport-parameters-e

const std = @import("std");
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
