package events

import "testing"

func TestAddEvent(t *testing.T) {

	M := NewManager()

	evt1 := NewEvent(nil, 100)
	evt2 := NewEvent(nil, 4002)
	evt3 := NewEvent(nil, 10440)

	M.AddEvent("testEvt", evt1)
	M.AddEvent("testEvt", evt2)
	M.AddEvent("testEvt", evt3)

	if len(M.events["testEvt"].events) != 3 {
		t.FailNow()
	}
}

func TestRemoveEvent(t *testing.T) {

	M := NewManager()

	evt1 := NewEvent(nil, 100)
	evt2 := NewEvent(nil, 4002)
	evt3 := NewEvent(nil, 10440)

	M.AddEvent("testEvt", evt1)
	M.AddEvent("testEvt", evt2)
	M.AddEvent("testEvt", evt3)

	M.RemoveEvent("testEvt")

	if _, ok := M.events["testEvt"]; ok {
		t.FailNow()
	}
}

func TestFireEvent(t *testing.T) {

	M := NewManager()

	evt1 := NewEvent(func(args ListenerArgs) {
		a := args["test"]
		if a != "1234" {
			t.FailNow()
		}
	}, 100)

	M.AddEvent("testEvt", evt1)
	M.FireEvent("testEvt", ListenerArgs{"test": "1234"})
}
