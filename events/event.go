package events

import "github.com/google/uuid"

type Event struct {
	ID       string
	Listener func(e Event)
	Args     map[string]interface{}
	Priority int
}

func NewEvent(listener func(e Event), priority int) *Event {
	return &Event{
		ID:       uuid.NewString(),
		Listener: listener,
		Priority: priority,
	}
}
