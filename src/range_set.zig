const std = @import("std");
const math = std.math;
const Treap = std.Treap;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const Range = struct {
    start: u64,
    end: u64,
};

/// Manage ranges to be ack'ed.
/// https://www.rfc-editor.org/rfc/rfc9000.html#ack-ranges
pub const RangeSet = struct {
    inner: InnerTree,
    allocator: Allocator,

    const Self = @This();
    const InnerTree = Treap(Range, compareRange);

    pub fn init(allocator: Allocator) Self {
        return .{
            .inner = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        const rec = struct {
            fn f(node: ?*InnerTree.Node, alloc: Allocator) void {
                const n = node orelse return;
                const left = n.*.children[0];
                f(left, alloc);
                const right = n.*.children[1];
                f(right, alloc);
                alloc.destroy(n);
            }
        }.f;

        rec(self.inner.root, self.allocator);
    }

    pub fn insert(self: *Self, range: Range) Allocator.Error!void {
        var start = range.start;
        var end = range.end;

        var cur_range = self.prev(start);
        while (cur_range) |r| {
            if (rangeOverlap(r.*, range)) {
                start = math.min(start, r.*.start);
                end = math.max(end, r.*.end);
                var entry = self.inner.getEntryFor(r.*);
                assert(entry.node != null);
                const orig_node_ptr = entry.node.?;
                defer self.allocator.destroy(orig_node_ptr);
                entry.set(null);
            } else {
                break;
            }
            cur_range = self.prev(start);
        }

        const new_range = Range{ .start = start, .end = end };
        var e = self.inner.getEntryFor(new_range);
        var node = try self.allocator.create(InnerTree.Node);
        node.key = new_range;
        e.set(node);
    }

    fn prev(self: Self, point: u64) ?*Range {
        const rec = struct {
            fn f(cur_node: ?*InnerTree.Node, x: u64, candidate: ?*Range) ?*Range {
                const n = cur_node orelse return candidate;

                const left = n.*.children[0];
                const right = n.*.children[1];

                return switch (compareRangeWithPoint(n.*.key, x)) {
                    .included => &n.*.key,
                    .smaller => f(left, x, candidate),
                    .greater => f(right, x, &n.*.key),
                };
            }
        }.f;

        return rec(self.inner.root, point, null);
    }

    fn next(self: Self, point: u64) ?*Range {
        const rec = struct {
            fn f(cur_node: ?*InnerTree.Node, x: u64, candidate: ?*Range) ?*Range {
                const n = cur_node orelse return candidate;

                const left = n.*.children[0];
                const right = n.*.children[1];

                return switch (compareRangeWithPoint(n.*.key, x)) {
                    .included => &n.*.key,
                    .smaller => f(right, x, &n.*.key),
                    .greater => f(left, x, candidate),
                };
            }
        }.f;

        return rec(self.inner.root, point, null);
    }
};

fn compareRange(a: Range, b: Range) math.Order {
    if (a.start != b.start)
        return math.order(a.start, b.start);

    return math.order(a.end, b.end);
}

fn compareRangeWithPoint(range: Range, point: u64) enum { smaller, included, greater } {
    if (point < range.start)
        return .smaller;

    if (range.end < point)
        return .greater;

    return .included;
}

fn rangeOverlap(smaller: Range, greater: Range) bool {
    return smaller.start <= greater.start and greater.start <= smaller.end;
}

test "RangeSet prev" {
    var set = RangeSet.init(std.testing.allocator);
    defer set.deinit();
    try set.insert(.{ .start = 1, .end = 3 });

    try std.testing.expect(set.prev(0) == null);

    try std.testing.expectEqual(@as(u64, 1), set.prev(1).?.start);
    try std.testing.expectEqual(@as(u64, 3), set.prev(1).?.end);

    try std.testing.expectEqual(@as(u64, 1), set.prev(2).?.start);
    try std.testing.expectEqual(@as(u64, 3), set.prev(2).?.end);

    try std.testing.expectEqual(@as(u64, 1), set.prev(3).?.start);
    try std.testing.expectEqual(@as(u64, 3), set.prev(3).?.end);

    try std.testing.expectEqual(@as(u64, 1), set.prev(4).?.start);
    try std.testing.expectEqual(@as(u64, 3), set.prev(4).?.end);

    // This will be merged with the range that was inserted above.
    try set.insert(.{ .start = 2, .end = 5 });

    try std.testing.expect(set.prev(0) == null);

    try std.testing.expectEqual(@as(u64, 1), set.prev(1).?.start);
    try std.testing.expectEqual(@as(u64, 5), set.prev(1).?.end);

    try std.testing.expectEqual(@as(u64, 1), set.prev(2).?.start);
    try std.testing.expectEqual(@as(u64, 5), set.prev(2).?.end);

    try std.testing.expectEqual(@as(u64, 1), set.prev(5).?.start);
    try std.testing.expectEqual(@as(u64, 5), set.prev(5).?.end);

    try std.testing.expectEqual(@as(u64, 1), set.prev(6).?.start);
    try std.testing.expectEqual(@as(u64, 5), set.prev(6).?.end);
}

test "RangeSet next" {
    var set = RangeSet.init(std.testing.allocator);
    defer set.deinit();
    try set.insert(.{ .start = 3, .end = 5 });

    try std.testing.expectEqual(@as(u64, 3), set.next(1).?.start);
    try std.testing.expectEqual(@as(u64, 5), set.next(1).?.end);

    try std.testing.expectEqual(@as(u64, 3), set.next(3).?.start);
    try std.testing.expectEqual(@as(u64, 5), set.next(3).?.end);

    try std.testing.expectEqual(@as(u64, 3), set.next(5).?.start);
    try std.testing.expectEqual(@as(u64, 5), set.next(5).?.end);

    try std.testing.expect(set.next(6) == null);
}
