package events

import "testing"

func TestReprioritise(t *testing.T) {

	Q := NewQueue()

	evt1 := NewEvent(nil, 100)
	evt2 := NewEvent(nil, 404)
	evt3 := NewEvent(nil, 2000)

	Q.Add(evt1)
	Q.Add(evt2)
	Q.Add(evt3)

	Q.reprioritise()
	if Q.priorityIndex[0] != evt3.ID {
		t.FailNow()
	}

	if Q.priorityIndex[2] != evt1.ID {
		t.FailNow()
	}
}

func TestRemove(t *testing.T) {

	Q := NewQueue()

	evt1 := NewEvent(nil, 100)
	evt2 := NewEvent(nil, 404)
	evt3 := NewEvent(nil, 2000)

	Q.Add(evt1)
	Q.Add(evt2)
	Q.Add(evt3)

	Q.Remove(&evt3)

	if _, ok := Q.events[evt3.ID]; ok {
		t.FailNow()
	}

	if Q.priorityIndex[0] != "" {
		t.FailNow()
	}
}

func TestDispose(t *testing.T) {

	Q := NewQueue()

	evt1 := NewEvent(nil, 100)
	evt2 := NewEvent(nil, 404)
	evt3 := NewEvent(nil, 2000)

	Q.Add(evt1)
	Q.Add(evt2)
	Q.Add(evt3)

	Q.Dispose()

	if Q.events != nil {
		t.FailNow()
	}
	if Q.priorityIndex != nil {
		t.FailNow()
	}

}

func TestIterateFunc(t *testing.T) {

	Q := NewQueue()

	evt1 := NewEvent(nil, 100)
	evt2 := NewEvent(nil, 404)
	evt3 := NewEvent(nil, 2000)

	Q.Add(evt1)
	Q.Add(evt2)
	Q.Add(evt3)

	evtIDs := make([]string, 0)

	Q.IterateFunc(func(e *Event) {
		evtIDs = append(evtIDs, e.ID)
	})

	if evtIDs[0] != evt3.ID {
		t.FailNow()
	}

}
