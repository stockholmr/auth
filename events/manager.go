package events

import "sync"

type Manager struct {
	sync.Mutex

	Events map[string]Queue
}




