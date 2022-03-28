package network

import "fmt"

type Path struct {
	Nodes []*Node
}

func (path *Path) Starter() (*Node, error) {
	if len(path.Nodes) == 0 {
		return nil, fmt.Errorf("path too short to get starting node")
	}

	return path.Nodes[0], nil
}

func (path *Path) Ender() (*Node, error) {
	if len(path.Nodes) == 0 {
		return nil, fmt.Errorf("path too short to get ending node")
	}

	return path.Nodes[len(path.Nodes)-1], nil
}

func (path *Path) CompoundReliability() float32 {
	var reliability float32 = 0.0

	for _, node := range path.Nodes {
		reliability = reliability * node.Reliability()
	}

	return reliability
}
