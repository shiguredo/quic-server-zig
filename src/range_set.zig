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
    const Node = InnerTree.Node;

    pub fn init(allocator: Allocator) Self {
        return .{
            .inner = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        const rec = struct {
            fn f(node: ?*Node, alloc: Allocator) void {
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
            if (!rangeOverlap(r.*, range))
                break;

            start = math.min(start, r.*.start);
            end = math.max(end, r.*.end);
            self.removeRange(r.*);
            cur_range = self.prev(start);
        }

        cur_range = self.next(start);
        while (cur_range) |r| {
            if (!rangeOverlap(range, r.*))
                break;

            start = math.min(start, r.*.start);
            end = math.max(end, r.*.end);
            self.removeRange(r.*);
            cur_range = self.next(start);
        }

        const new_range = Range{ .start = start, .end = end };
        var e = self.inner.getEntryFor(new_range);
        var node = try self.allocator.create(Node);
        node.key = new_range;
        e.set(node);
    }

    fn prev(self: Self, point: u64) ?*Range {
        const rec = struct {
            fn f(cur_node: ?*Node, x: u64, candidate: ?*Range) ?*Range {
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
            fn f(cur_node: ?*Node, x: u64, candidate: ?*Range) ?*Range {
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

    fn removeRange(self: *Self, range: Range) void {
        var entry = self.inner.getEntryFor(range);
        const orig_node_ptr = entry.node orelse return;
        defer self.allocator.destroy(orig_node_ptr);
        entry.set(null);
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

test {
    _ = RangeSetTest;
}

const RangeSetTest = struct {
    fn count(set: RangeSet) usize {
        const rec = struct {
            fn f(node: ?*RangeSet.Node) usize {
                const n = node orelse return 0;
                const left = n.*.children[0];
                const right = n.*.children[1];
                return 1 + f(left) + f(right);
            }
        }.f;

        return rec(set.inner.root);
    }

    test "insert" {
        var set = RangeSet.init(std.testing.allocator);
        defer set.deinit();

        try set.insert(.{ .start = 1, .end = 3 });
        try std.testing.expectEqual(@as(usize, 1), count(set));

        // This will be merged with the first range, expanding the range to [1, 4].
        try set.insert(.{ .start = 2, .end = 4 });
        try std.testing.expectEqual(@as(usize, 1), count(set));

        // This will be merged with the first range, with no expansion.
        try set.insert(.{ .start = 1, .end = 2 });
        try std.testing.expectEqual(@as(usize, 1), count(set));

        // This will be merged with the first range, expanding the range to [0, 5].
        try set.insert(.{ .start = 0, .end = 5 });
        try std.testing.expectEqual(@as(usize, 1), count(set));

        // This will NOT be merged with the existing range.
        try set.insert(.{ .start = 8, .end = 10 });
        try std.testing.expectEqual(@as(usize, 2), count(set));

        // This overlaps with the existing two ranges.
        // As a result we will get a single range of [0, 10].
        try set.insert(.{ .start = 4, .end = 9 });
        try std.testing.expectEqual(@as(usize, 1), count(set));
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

        // This will be merged with the range that was inserted above.
        try set.insert(.{ .start = 4, .end = 7 });

        try std.testing.expectEqual(@as(u64, 3), set.next(1).?.start);
        try std.testing.expectEqual(@as(u64, 7), set.next(1).?.end);

        try std.testing.expectEqual(@as(u64, 3), set.next(3).?.start);
        try std.testing.expectEqual(@as(u64, 7), set.next(3).?.end);

        try std.testing.expectEqual(@as(u64, 3), set.next(7).?.start);
        try std.testing.expectEqual(@as(u64, 7), set.next(7).?.end);

        try std.testing.expect(set.next(8) == null);
    }
};
