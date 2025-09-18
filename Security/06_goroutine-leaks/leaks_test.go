package leaks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// blockedIn counts goroutines whose stack shows them blocked in a channel
// send inside fn. It reads the stacks of all goroutines, which is precise
// where runtime.NumGoroutine deltas are noisy.
func blockedIn(fn string) int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		if bytes.Contains(g, []byte("[chan send")) && bytes.Contains(g, []byte(fn)) {
			n++
		}
	}
	return n
}

// TestFetchUnsafeLeaks cannot run inside a synctest bubble: the leaked
// goroutines would make synctest.Test fail. It leaks them into the test
// binary on purpose and counts them by stack.
func TestFetchUnsafeLeaks(t *testing.T) {
	const calls = 50
	release := make(chan struct{})
	slow := func(context.Context) string { <-release; return "late" }

	for range calls {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // the caller has already timed out
		if _, err := FetchUnsafe(ctx, slow); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	}
	close(release) // the backend answers; nobody is listening

	deadline := time.Now().Add(2 * time.Second)
	for blockedIn("leaks.FetchUnsafe.func1") < calls {
		if time.Now().After(deadline) {
			t.Fatalf("only %d goroutines stuck in send", blockedIn("leaks.FetchUnsafe.func1"))
		}
		runtime.Gosched()
	}
}

// TestFetchDoesNotLeak runs the same scenario in a bubble. synctest.Test
// fails if any goroutine started inside it is still blocked when the test
// function returns, so passing is the proof of no leak. With FetchUnsafe in
// place of Fetch this test fails with a deadlock report.
func TestFetchDoesNotLeak(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		// A worker that ignores ctx and takes 2s against a 1s budget.
		slow := func(context.Context) string { time.Sleep(2 * time.Second); return "late" }

		_, err := FetchWithTimeout(t.Context(), time.Second, slow)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
		if d := time.Since(start); d != time.Second {
			t.Fatalf("returned after %v (fake clock), want 1s", d)
		}
		time.Sleep(2 * time.Second) // let the worker finish and exit
		synctest.Wait()
	})
}

func TestFetchStopsCancellationAwareWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var stopped atomic.Bool
		work := func(ctx context.Context) string {
			select {
			case <-time.After(time.Hour):
				return "done"
			case <-ctx.Done():
				stopped.Store(true)
				return ""
			}
		}
		if _, err := FetchWithTimeout(t.Context(), 100*time.Millisecond, work); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
		synctest.Wait()
		if !stopped.Load() {
			t.Fatal("worker kept running after the deadline")
		}
	})
}

func items(n int) []string {
	s := make([]string, n)
	for i := range s {
		s[i] = "item-" + strconv.Itoa(i)
	}
	return s
}

func TestProcessAllUnsafeIsUnbounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		var inflight atomic.Int64
		done := make(chan struct{})
		go func() {
			ProcessAllUnsafe(items(1000), func(string) { inflight.Add(1); <-gate })
			close(done)
		}()
		synctest.Wait() // every goroutine is now blocked on the gate
		if got := inflight.Load(); got != 1000 {
			t.Fatalf("in flight = %d, want all 1000", got)
		}
		close(gate)
		<-done
	})
}

func TestProcessAllIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		var inflight, total atomic.Int64
		done := make(chan error)
		go func() {
			done <- ProcessAll(t.Context(), items(1000), 8, func(context.Context, string) {
				inflight.Add(1)
				total.Add(1)
				<-gate
				inflight.Add(-1)
			})
		}()
		synctest.Wait()
		if got := inflight.Load(); got != 8 {
			t.Fatalf("in flight = %d, want 8", got)
		}
		close(gate)
		if err := <-done; err != nil || total.Load() != 1000 {
			t.Fatalf("err = %v, processed %d", err, total.Load())
		}
	})
}

func TestProcessAllStopsOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		var started atomic.Int64
		done := make(chan error)
		go func() {
			done <- ProcessAll(ctx, items(1000), 4, func(ctx context.Context, _ string) {
				started.Add(1)
				<-ctx.Done()
			})
		}()
		synctest.Wait()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
		if started.Load() != 4 {
			t.Fatalf("started %d items after cancellation, want 4", started.Load())
		}
	})
}

func ExampleFetchWithTimeout() {
	ctx := context.Background()
	v, err := FetchWithTimeout(ctx, time.Second, func(context.Context) string { return "ok" })
	fmt.Println(v, err)
	// Output:
	// ok <nil>
}
