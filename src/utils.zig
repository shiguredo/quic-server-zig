const std = @import("std");

/// Calculates how many bytes a value of type `T` takes in the memory.
/// This is not always identical to the builtin `@sizeOf` because the builtin
/// one takes padding into account, while this function does not.
/// J
/// For instance, `@sizeOf(u24)` returns `4` on 64 bit machines, while this returns `3`.
pub fn sizeOf(comptime T: type) comptime_int {
    return @divExact(@typeInfo(T).Int.bits, 8);
}

test "sizeOf" {
    try std.testing.expectEqual(1, sizeOf(u8));
    try std.testing.expectEqual(2, sizeOf(u16));
    try std.testing.expectEqual(3, sizeOf(u24));
    try std.testing.expectEqual(4, sizeOf(u32));
    try std.testing.expectEqual(8, sizeOf(u64));
}
