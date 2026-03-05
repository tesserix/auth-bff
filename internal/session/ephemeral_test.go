package session

import (
	"testing"
	"time"
)

func TestEphemeralStore_SetAndGet(t *testing.T) {
	store := NewEphemeralStore()

	store.Set("key1", []byte("value1"), 5*time.Minute)

	data, ok := store.Get("key1")
	if !ok {
		t.Fatal("expected key1 to exist")
	}
	if string(data) != "value1" {
		t.Errorf("got %q, want %q", string(data), "value1")
	}
}

func TestEphemeralStore_Get_NotFound(t *testing.T) {
	store := NewEphemeralStore()

	_, ok := store.Get("nonexistent")
	if ok {
		t.Error("expected nonexistent key to return false")
	}
}

func TestEphemeralStore_Get_Expired(t *testing.T) {
	store := NewEphemeralStore()

	store.Set("key1", []byte("value1"), 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	_, ok := store.Get("key1")
	if ok {
		t.Error("expected expired key to return false")
	}
}

func TestEphemeralStore_Consume(t *testing.T) {
	store := NewEphemeralStore()

	store.Set("key1", []byte("value1"), 5*time.Minute)

	// First consume should succeed
	data, ok := store.Consume("key1")
	if !ok {
		t.Fatal("first consume should succeed")
	}
	if string(data) != "value1" {
		t.Errorf("got %q, want %q", string(data), "value1")
	}

	// Second consume should fail (single-use)
	_, ok = store.Consume("key1")
	if ok {
		t.Error("second consume should fail")
	}
}

func TestEphemeralStore_Consume_Expired(t *testing.T) {
	store := NewEphemeralStore()

	store.Set("key1", []byte("value1"), 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	_, ok := store.Consume("key1")
	if ok {
		t.Error("consume of expired key should fail")
	}
}

func TestEphemeralStore_Delete(t *testing.T) {
	store := NewEphemeralStore()

	store.Set("key1", []byte("value1"), 5*time.Minute)
	store.Delete("key1")

	_, ok := store.Get("key1")
	if ok {
		t.Error("deleted key should not exist")
	}
}

func TestEphemeralStore_Overwrite(t *testing.T) {
	store := NewEphemeralStore()

	store.Set("key1", []byte("value1"), 5*time.Minute)
	store.Set("key1", []byte("value2"), 5*time.Minute)

	data, ok := store.Get("key1")
	if !ok {
		t.Fatal("expected key1 to exist")
	}
	if string(data) != "value2" {
		t.Errorf("got %q, want %q (overwrite should win)", string(data), "value2")
	}
}

func TestEphemeralStore_ConcurrentAccess(t *testing.T) {
	store := NewEphemeralStore()
	done := make(chan bool, 100)

	// Concurrent writes
	for i := 0; i < 50; i++ {
		go func(i int) {
			store.Set("key", []byte("value"), 5*time.Minute)
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		go func() {
			store.Get("key")
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}
