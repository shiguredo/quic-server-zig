//! https://www.rfc-editor.org/rfc/rfc5915#section-3
//!
//! ECPrivateKey ::= SEQUENCE {
//!   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//!   privateKey     OCTET STRING,
//!   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
//!   publicKey  [1] BIT STRING OPTIONAL
//! }

const std = @import("std");
const io = std.io;
const Allocator = std.mem.Allocator;
const Parser = @import("./der.zig").Parser;

private_key: []const u8,

allocator: Allocator,

const Self = @This();

pub fn parseDer(allocator: Allocator, der: []const u8) !Self {
    var stream = io.fixedBufferStream(der);
    const reader = stream.reader();

    const id = try Parser.consumeIdentifier(reader);
    if (id != .SEQUENCE)
        return error.InvalidDER;

    _ = try Parser.consumeLength(reader);

    const version = try Parser.consumeInteger(reader);
    if (version != 1)
        return error.InvalidDER;

    const private_key = try Parser.consumeOctetString(allocator, reader);

    return Self{
        .private_key = private_key,
        .allocator = allocator,
    };

    // TODO(magurotuna): parse the remaining fields
}

pub fn deinit(self: Self) void {
    self.allocator.free(self.private_key);
}
