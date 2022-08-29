const std = @import("std");
const VariableLengthVector = @import("../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../bytes.zig").Bytes;

pub const Extension = struct {
    extension_type: ExtensionType,
    extension_data: ExtensionData,

    const Self = @This();
    const ExtensionData = VariableLengthVector(u8, 65535);

    pub fn encodedLength(self: Self) usize {
        var len: usize = 0;
        for (@typeInfo(Self).Struct.fields) |field| {
            len += @field(self, field.name).encodedLength();
        }
        return len;
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        for (@typeInfo(Self).Struct.fields) |field| {
            try @field(self, field.name).encode(out);
        }
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        const ty = try ExtensionType.decode(allocator, in);
        errdefer ty.deinit();

        const data = try ExtensionData.decode(allocator, in);
        errdefer data.deinit();

        return Self{
            .extension_type = ty,
            .extension_data = data,
        };
    }

    pub fn deinit(self: Self) void {
        self.extension_data.deinit();
    }
};

pub const ExtensionType = enum(u16) {
    // zig fmt: off
    server_name = 0,                             // RFC 6066
    max_fragment_length = 1,                     // RFC 6066
    status_request = 5,                          // RFC 6066
    supported_groups = 10,                       // RFC 8422, 7919
    signature_algorithms = 13,                   // RFC 8446
    use_srtp = 14,                               // RFC 5764
    heartbeat = 15,                              // RFC 6520
    application_layer_protocol_negotiation = 16, // RFC 7301
    signed_certificate_timestamp = 18,           // RFC 6962
    client_certificate_type = 19,                // RFC 7250
    server_certificate_type = 20,                // RFC 7250
    padding = 21,                                // RFC 7685
    RESERVED_1 = 40,                             // Used but never assigned
    pre_shared_key = 41,                         // RFC 8446
    early_data = 42,                             // RFC 8446
    supported_versions = 43,                     // RFC 8446
    cookie = 44,                                 // RFC 8446
    psk_key_exchange_modes = 45,                 // RFC 8446
    RESERVED_2 = 46,                             // Used but never assigned
    certificate_authorities = 47,                // RFC 8446
    oid_filters = 48,                            // RFC 8446
    post_handshake_auth = 49,                    // RFC 8446
    signature_algorithms_cert = 50,              // RFC 8446
    key_share = 51,                              // RFC 8446
    // zig fmt: on

    const Self = @This();
    const TagType = @typeInfo(Self).Enum.tag_type;

    pub fn encodedLength(self: Self) usize {
        _ = self;
        return @sizeOf(TagType);
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.put(TagType, @enumToInt(self));
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        _ = allocator;
        const val = try in.consume(TagType);
        return @intToEnum(Self, val);
    }

    pub fn deinit(self: Self) void {
        // no-op
        _ = self;
    }
};
