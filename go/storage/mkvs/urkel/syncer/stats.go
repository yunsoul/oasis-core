package syncer

import (
	"context"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

// StatsCollector is a ReadSyncer which collects call statistics.
type StatsCollector struct {
	SubtreeFetches int
	PathFetches    int
	NodeFetches    int
	ValueFetches   int

	rs ReadSyncer
}

// NewnopReadSyncer creates a new no-op read syncer.
func NewStatsCollector(rs ReadSyncer) *StatsCollector {
	return &StatsCollector{
		rs: rs,
	}
}

// GetSubtree retrieves a compressed subtree summary of the given root.
func (c *StatsCollector) GetSubtree(ctx context.Context, root node.Root, id node.ID, maxDepth node.Depth) (*Subtree, error) {
	c.SubtreeFetches++
	return c.rs.GetSubtree(ctx, root, id, maxDepth)
}

func (c *StatsCollector) GetPath(ctx context.Context, root node.Root, key node.Key, startDepth node.Depth) (*Subtree, error) {
	c.PathFetches++
	return c.rs.GetPath(ctx, root, key, startDepth)
}

// GetNode retrieves a specific node under the given root.
func (c *StatsCollector) GetNode(ctx context.Context, root node.Root, id node.ID) (node.Node, error) {
	c.NodeFetches++
	return c.rs.GetNode(ctx, root, id)
}
