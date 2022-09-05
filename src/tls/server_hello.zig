const std = @import("std");
const VariableLengthVector = @import("../variable_length_vector.zig").VariableLengthVector;
const Bytes = @import("../bytes.zig").Bytes;
const Extension = @import("./extension.zig").Extension;
const utils = @import("../utils.zig");

/// https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3
///
/// uint16 ProtocolVersion;
/// opaque Random[32];
///
/// uint8 CipherSuite[2];    /* Cryptographic suite selector */
///
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id_echo<0..32>;
///     CipherSuite cipher_suite;
///     uint8 legacy_compression_method = 0;
///     Extension extensions<6..2^16-1>;
/// } ServerHello;
pub const ServerHello = struct {
    const ProtocolVersion = u16;
    const Random = [32]u8;
    const LegacySessionId = VariableLengthVector(u8, 32);
    const CipherSuite = [2]u8;
    const LegacyCompressionMethod = u8;
    const Extensions = VariableLengthVector(Extension(.server), 65535);

    const legacy_version: ProtocolVersion = 0x0303;
    const legacy_compression_method: LegacyCompressionMethod = 0;

    legacy_version: u16 = legacy_version,
    random: Random,
    legacy_session_id_echo: LegacySessionId,
    cipher_suite: CipherSuite,
    legacy_compression_method: LegacyCompressionMethod = legacy_compression_method,
    extensions: Extensions,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        var len: usize = 0;
        len += utils.sizeOf(ProtocolVersion);
        len += utils.sizeOf(Random);
        len += self.legacy_session_id_echo.encodedLength();
        len += utils.sizeOf(CipherSuite);
        len += utils.sizeOf(@TypeOf(self.legacy_compression_method));
        len += self.extensions.encodedLength();
        return len;
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.put(ProtocolVersion, self.legacy_version);
        try out.putBytes(&self.random);
        try self.legacy_session_id_echo.encode(out);
        try out.putBytes(&self.cipher_suite);
        try out.put(LegacyCompressionMethod, self.legacy_compression_method);
        try self.extensions.encode(out);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        // TODO(magurotuna): implement
        _ = allocator;
        _ = in;
        return error.Unimplemented;
    }

    pub fn deinit(self: Self) void {
        self.legacy_session_id_echo.deinit();
        self.extensions.deinit();
    }
};
