const std = @import("std");
const log = std.log;
const meta = std.meta;
const VariableLengthVector = @import("../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../bytes.zig").Bytes;
const utils = @import("../utils.zig");
const supported_versions = @import("./extension/supported_versions.zig");
const ServerNameList = @import("./extension/server_name.zig").ServerNameList;
const RenegotiationInfo = @import("./extension/renegotiation_info.zig").RenegotiationInfo;
const NamedGroupList = @import("./extension/supported_groups.zig").NamedGroupList;
const SessionTicket = @import("./extension/session_ticket.zig").SessionTicket;
const key_share = @import("./extension/key_share.zig");
const SignatureSchemeList = @import("./extension/signature_algorithms.zig").SignatureSchemeList;
const PskKeyExchangeModes = @import("./extension/psk_key_exchange_modes.zig").PskKeyExchangeModes;
const RecordSizeLimit = @import("./extension/record_size_limit.zig").RecordSizeLimit;
const ApplicationLayerProtocolNegotiation = @import("./extension/application_layer_protocol_negotiation.zig").ApplicationLayerProtocolNegotiation;
const QuicTransportParameters = @import("./extension/quic_transport_parameters.zig").TransportParameters;
const StatusRequest = @import("./extension/status_request.zig").CertificateStatusRequest;
const ECPointFormats = @import("./extension/ec_point_formats.zig").ECPointFormatList;
const ExtendedMasterSecret = @import("./extension/extended_master_secret.zig").ExtendedMasterSecret;

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2
///
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
pub fn Extension(comptime endpoint_kind: enum { server, client }) type {
    return union(ExtensionType) {
        server_name: ServerNameList,
        max_fragment_length: UnimplementedExtension,
        status_request: StatusRequest,
        supported_groups: NamedGroupList,
        ec_point_formats: ECPointFormats,
        signature_algorithms: SignatureSchemeList,
        use_srtp: UnimplementedExtension,
        heartbeat: UnimplementedExtension,
        application_layer_protocol_negotiation: ApplicationLayerProtocolNegotiation,
        signed_certificate_timestamp: UnimplementedExtension,
        client_certificate_type: UnimplementedExtension,
        server_certificate_type: UnimplementedExtension,
        padding: UnimplementedExtension,
        extended_master_secret: ExtendedMasterSecret,
        record_size_limit: RecordSizeLimit,
        session_ticket: SessionTicket,
        RESERVED_1: UnimplementedExtension,
        pre_shared_key: UnimplementedExtension,
        early_data: UnimplementedExtension,
        supported_versions: switch (endpoint_kind) {
            .server => supported_versions.ServerSupportedVersions,
            .client => supported_versions.ClientSupportedVersions,
        },
        cookie: UnimplementedExtension,
        psk_key_exchange_modes: PskKeyExchangeModes,
        RESERVED_2: UnimplementedExtension,
        certificate_authorities: UnimplementedExtension,
        oid_filters: UnimplementedExtension,
        post_handshake_auth: UnimplementedExtension,
        signature_algorithms_cert: UnimplementedExtension,
        key_share: switch (endpoint_kind) {
            .server => key_share.KeyShareServerHello,
            .client => key_share.KeyShareClientHello,
        },
        quic_transport_parameters: QuicTransportParameters,
        renegotiation_info: RenegotiationInfo,
        unknown: UnknownExtension,

        const Self = @This();
        /// A `extension_data` field is variable-length vector whose maximum length is 2^16 - 1.
        /// u16 is necessary to represent this number.
        const ExtensionDataLengthType = u16;

        pub fn encodedLength(self: Self) usize {
            var len: usize = 0;
            len += utils.sizeOf(ExtensionType.TagType);
            len += utils.sizeOf(ExtensionDataLengthType);
            len += switch (self) {
                .server_name => |s| s.encodedLength(),
                .status_request => |s| s.encodedLength(),
                .supported_groups => |s| s.encodedLength(),
                .ec_point_formats => |e| e.encodedLength(),
                .signature_algorithms => |s| s.encodedLength(),
                .application_layer_protocol_negotiation => |a| a.encodedLength(),
                .extended_master_secret => |e| e.encodedLength(),
                .record_size_limit => |r| r.encodedLength(),
                .session_ticket => |s| s.encodedLength(),
                .supported_versions => |s| s.encodedLength(),
                .psk_key_exchange_modes => |p| p.encodedLength(),
                .key_share => |k| k.encodedLength(),
                .quic_transport_parameters => |q| q.encodedLength(),
                .renegotiation_info => |r| r.encodedLength(),
                .unknown => 0,
                // TODO(magurotuna): implement other extensions
                else => 0,
            };
            return len;
        }

        pub fn encode(self: Self, out: *Bytes) !void {
            if (self == .unknown)
                return error.UnknownExtension;

            // extension_type
            try out.put(ExtensionType.TagType, @enumToInt(self));

            // length of extension_data
            try out.put(ExtensionDataLengthType, @intCast(ExtensionDataLengthType, switch (self) {
                .server_name => |s| s.encodedLength(),
                .status_request => |s| s.encodedLength(),
                .supported_groups => |s| s.encodedLength(),
                .ec_point_formats => |e| e.encodedLength(),
                .signature_algorithms => |s| s.encodedLength(),
                .application_layer_protocol_negotiation => |a| a.encodedLength(),
                .extended_master_secret => |e| e.encodedLength(),
                .record_size_limit => |r| r.encodedLength(),
                .session_ticket => |s| s.encodedLength(),
                .supported_versions => |s| s.encodedLength(),
                .psk_key_exchange_modes => |p| p.encodedLength(),
                .key_share => |k| k.encodedLength(),
                .quic_transport_parameters => |q| q.encodedLength(),
                .renegotiation_info => |r| r.encodedLength(),
                // TODO(magurotuna): implement other extensions
                else => return error.Unimplemented,
            }));

            // exntension data
            switch (self) {
                .server_name => |s| try s.encode(out),
                .status_request => |s| try s.encode(out),
                .supported_groups => |s| try s.encode(out),
                .ec_point_formats => |e| try e.encode(out),
                .signature_algorithms => |s| try s.encode(out),
                .application_layer_protocol_negotiation => |a| try a.encode(out),
                .extended_master_secret => |e| try e.encode(out),
                .record_size_limit => |r| try r.encode(out),
                .session_ticket => |s| try s.encode(out),
                .supported_versions => |s| try s.encode(out),
                .psk_key_exchange_modes => |p| try p.encode(out),
                .key_share => |k| try k.encode(out),
                .quic_transport_parameters => |q| try q.encode(out),
                .renegotiation_info => |r| try r.encode(out),
                // TODO(magurotuna): implement other extensions
                else => return error.Unimplemented,
            }
        }

        pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
            // Decode `extension_type`.
            const ty_num = try in.consume(ExtensionType.TagType);

            // Decode the length of `extension_data`.
            const data_len = try in.consume(ExtensionDataLengthType);

            // Create new `Bytes` that only views the range being decoded as a extension_data.
            var data_in = Bytes{ .buf = try in.consumeBytes(data_len) };

            // If the `extension_type` is an unknown one we treat it as `UnknownExtension`.
            const ty = meta.intToEnum(ExtensionType, ty_num) catch |e| {
                if (e == meta.IntToEnumError.InvalidEnumTag) {
                    return .{
                        .unknown = try UnknownExtension.decode(allocator, &data_in, ty_num),
                    };
                }

                return e;
            };

            // Decode the content of `extension_data`.
            return switch (ty) {
                .server_name => .{
                    .server_name = try ServerNameList.decode(allocator, &data_in),
                },
                .status_request => .{
                    .status_request = try StatusRequest.decode(allocator, &data_in),
                },
                .supported_groups => .{
                    .supported_groups = try NamedGroupList.decode(allocator, &data_in),
                },
                .ec_point_formats => .{
                    .ec_point_formats = try ECPointFormats.decode(allocator, &data_in),
                },
                .signature_algorithms => .{
                    .signature_algorithms = try SignatureSchemeList.decode(allocator, &data_in),
                },
                .application_layer_protocol_negotiation => .{
                    .application_layer_protocol_negotiation = try ApplicationLayerProtocolNegotiation.decode(allocator, &data_in),
                },
                .extended_master_secret => .{
                    .extended_master_secret = try ExtendedMasterSecret.decode(allocator, &data_in),
                },
                .record_size_limit => .{
                    .record_size_limit = try RecordSizeLimit.decode(allocator, &data_in),
                },
                .session_ticket => .{
                    .session_ticket = try SessionTicket.decode(allocator, &data_in),
                },
                .supported_versions => .{
                    .supported_versions = switch (endpoint_kind) {
                        .server => try supported_versions.ServerSupportedVersions.decode(allocator, &data_in),
                        .client => try supported_versions.ClientSupportedVersions.decode(allocator, &data_in),
                    },
                },
                .psk_key_exchange_modes => .{
                    .psk_key_exchange_modes = try PskKeyExchangeModes.decode(allocator, &data_in),
                },
                .key_share => .{
                    .key_share = switch (endpoint_kind) {
                        .server => try key_share.KeyShareServerHello.decode(allocator, &data_in),
                        .client => try key_share.KeyShareClientHello.decode(allocator, &data_in),
                    },
                },
                .quic_transport_parameters => .{
                    .quic_transport_parameters = try QuicTransportParameters.decode(allocator, &data_in),
                },
                .renegotiation_info => .{
                    .renegotiation_info = try RenegotiationInfo.decode(allocator, &data_in),
                },
                .unknown => unreachable,
                // TODO(magurotuna): implement other extensions
                else => {
                    log.debug("Unsupported extension type detected: {}\n", .{ty});
                    return error.Unimplemented;
                },
            };
        }

        pub fn deinit(self: Self) void {
            switch (self) {
                .server_name => |s| s.deinit(),
                .status_request => |s| s.deinit(),
                .supported_groups => |s| s.deinit(),
                .ec_point_formats => |e| e.deinit(),
                .signature_algorithms => |s| s.deinit(),
                .application_layer_protocol_negotiation => |a| a.deinit(),
                .extended_master_secret => |e| e.deinit(),
                .record_size_limit => |r| r.deinit(),
                .session_ticket => |s| s.deinit(),
                .supported_versions => |s| s.deinit(),
                .psk_key_exchange_modes => |p| p.deinit(),
                .key_share => |k| k.deinit(),
                .quic_transport_parameters => |q| q.deinit(),
                .renegotiation_info => |r| r.deinit(),
                .unknown => |u| u.deinit(),
                // TODO(magurotuna): implement other extensions
                else => unreachable,
            }
        }
    };
}

test "encode Extension" {
    const ext = Extension(.server){
        .supported_versions = .{
            .selected_version = 0x00_01,
        },
    };
    defer ext.deinit();
    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ext.encode(&out);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x2b, 0x00, 0x02, 0x00, 0x01 }, out.split().former.buf);
}

test "decode Extension" {
    var buf = [_]u8{ 0x00, 0x2b, 0x00, 0x02, 0x00, 0x01 };
    var in = Bytes{ .buf = &buf };

    const got = try Extension(.server).decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(
        @as(supported_versions.ProtocolVersion, 0x00_01),
        got.supported_versions.selected_version,
    );
}

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.2
///
/// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
pub const ExtensionType = enum(u16) {
    // zig fmt: off
    server_name = 0,                             // RFC 6066
    max_fragment_length = 1,                     // RFC 6066
    status_request = 5,                          // RFC 6066
    supported_groups = 10,                       // RFC 8422, 7919
    ec_point_formats = 11,                       // RFC 8422
    signature_algorithms = 13,                   // RFC 8446
    use_srtp = 14,                               // RFC 5764
    heartbeat = 15,                              // RFC 6520
    application_layer_protocol_negotiation = 16, // RFC 7301
    signed_certificate_timestamp = 18,           // RFC 6962
    client_certificate_type = 19,                // RFC 7250
    server_certificate_type = 20,                // RFC 7250
    padding = 21,                                // RFC 7685
    extended_master_secret = 23,                 // RFC 7627
    record_size_limit = 28,                      // RFC 8449
    session_ticket = 35,                         // RFC 5077, 8447
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
    quic_transport_parameters = 57,              // RFC 9000, 9001
    renegotiation_info = 65281,                  // RFC 5746

    // Only used when the peer sends an extension unknown to us.
    unknown = 65535,
    // zig fmt: on

    const Self = @This();
    const TagType = @typeInfo(Self).Enum.tag_type;
};

const UnimplementedExtension = struct {};

const UnknownExtension = struct {
    extension_type_number: ExtensionType.TagType,
    data: Data,

    const Self = @This();
    const Data = VariableLengthVector(u8, 65535);

    fn decode(allocator: std.mem.Allocator, in: *Bytes, type_number: ExtensionType.TagType) !Self {
        return Self{
            .extension_type_number = type_number,
            .data = try Data.decode(allocator, in),
        };
    }

    fn deinit(self: Self) void {
        self.data.deinit();
    }
};
