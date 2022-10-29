package events

import "github.com/google/uuid"

type ListenerArgs map[string]interface{}

type Event struct {
	ID       string
	Listener func(ListenerArgs)
	Priority int
}

func NewEvent(listener func(ListenerArgs), priority int) Event {
	return Event{
		ID:       uuid.NewString(),
		Listener: listener,
		Priority: priority,
	}
}

func (E *Event) Dispose() {
	E.ID = ""
	E.Priority = -1
	E.Listener = nil
}
