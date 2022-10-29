package events

import (
	"errors"
	"sort"
	"strings"

	"golang.org/x/exp/slices"
)

type Queue struct {
	events        map[string]Event
	priorityIndex []string
}

func NewQueue() *Queue {
	return &Queue{
		events:        make(map[string]Event, 0),
		priorityIndex: make([]string, 0),
	}
}

func (Q *Queue) reprioritise() {
	sort.Slice(Q.priorityIndex, func(i, j int) bool {
		return Q.events[Q.priorityIndex[i]].Priority > Q.events[Q.priorityIndex[j]].Priority
	})
}

func (Q *Queue) Add(e Event) error {
	if _, ok := Q.events[e.ID]; ok {
		return errors.New("event id already exists")
	}
	Q.events[e.ID] = e
	Q.priorityIndex = append(Q.priorityIndex, e.ID)
	Q.reprioritise()
	return nil
}

func (Q *Queue) Remove(e *Event) {
	for _, evt := range Q.events {
		if strings.Compare(evt.ID, e.ID) == 0 {
			ID := evt.ID
			evt.Dispose()
			delete(Q.events, ID)
			priorityIndex := slices.IndexFunc(Q.priorityIndex, func(id string) bool { return id == e.ID })
			Q.priorityIndex[priorityIndex] = ""
		}
	}
}

func (Q *Queue) Dispose() {
	for _, evt := range Q.events {
		ID := evt.ID
		evt.Dispose()
		delete(Q.events, ID)
	}
	Q.priorityIndex = nil
	Q.events = nil
}

func (Q *Queue) IterateFunc(f func(e *Event)) {
	for _, ID := range Q.priorityIndex {
		if ID != "" {
			event := Q.events[ID]
			f(&event)
		}
	}
}
