package events

import "sync"

type ListenerQueue map[string]*Queue

type Manager struct {
	sync.Mutex

	events ListenerQueue
}

func NewManager() *Manager {
	return &Manager{
		events: make(ListenerQueue, 0),
	}
}

func (M *Manager) AddEvent(name string, e Event) {
	if _, ok := M.events[name]; !ok {
		M.events[name] = NewQueue()
	}
	M.events[name].Add(e)
}

func (M *Manager) RemoveEvent(name string) {
	if _, ok := M.events[name]; ok {
		M.events[name].Dispose()
		delete(M.events, name)
	}
}

func (M *Manager) FireEvent(name string, args ListenerArgs) {
	if _, ok := M.events[name]; ok {
		M.events[name].IterateFunc(func(e *Event) {
			if e.Listener != nil {
				e.Listener(args)
			}
		})
	}
}
