const std = @import("std");

pub const quic_v1 = 0x0000_0001;

pub fn isSupported(version: u32) bool {
    return version == quic_v1;
}

test "supported version check" {
    const draft27 = 0xff00_001b;
    const draft28 = 0xff00_001c;
    const draft29 = 0xff00_001d;

    try std.testing.expect(!isSupported(draft27));
    try std.testing.expect(!isSupported(draft28));
    try std.testing.expect(!isSupported(draft29));
    try std.testing.expect(isSupported(0x0000_0001));
}
