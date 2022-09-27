const std = @import("std");
const math = std.math;
const Treap = std.Treap;
const Allocator = std.mem.Allocator;

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
        // TODO
        var e = self.inner.getEntryFor(range);
        var node = try self.allocator.create(InnerTree.Node);
        node.key = range;
        e.set(node);
    }

    fn prev(self: Self, point: u64) ?*Range {
        const rec = struct {
            fn cmp(range: Range, x: u64) enum { smaller, included, greater } {
                if (x < range.start)
                    return .smaller;

                if (range.end < x)
                    return .greater;

                return .included;
            }

            fn f(cur_node: ?*InnerTree.Node, x: u64, candidate: ?*Range) ?*Range {
                const n = cur_node orelse return candidate;

                const left = n.*.children[0];
                const right = n.*.children[1];

                return switch (cmp(n.*.key, x)) {
                    .included => &n.*.key,
                    .smaller => f(left, x, candidate),
                    .greater => f(right, x, &n.*.key),
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
}
