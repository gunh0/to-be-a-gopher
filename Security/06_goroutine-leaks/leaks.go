// Package leaks shows how goroutines outlive the request that started them —
// blocked on a channel nobody reads, or spawned without a bound — and how
// buffered results, context cancellation and semaphores keep goroutine count
// proportional to work actually in progress.
package leaks

import (
	"context"
	"sync"
	"time"
)

// FetchUnsafe runs work in a goroutine and returns its result, or the
// context's error if the caller gives up first. The result channel is
// unbuffered: after a timeout nobody will ever receive, so the worker blocks
// on its send forever. Goroutines are not garbage collected; each timed-out
// request leaks one goroutine, its stack and everything it references
// (CWE-772). An attacker who can make the backend slow turns every request
// into a permanent allocation.
func FetchUnsafe(ctx context.Context, work func(context.Context) string) (string, error) {
	ch := make(chan string)
	go func() { ch <- work(ctx) }()
	select {
	case v := <-ch:
		return v, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Fetch gives the result channel one slot of buffer, so the worker's send
// always completes and the goroutine exits even when nobody is listening.
// The work function also receives ctx, so a cancellation-aware worker stops
// early instead of finishing work whose result will be dropped.
func Fetch(ctx context.Context, work func(context.Context) string) (string, error) {
	ch := make(chan string, 1)
	go func() { ch <- work(ctx) }()
	select {
	case v := <-ch:
		return v, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// FetchWithTimeout bounds Fetch by d. The deferred cancel releases the
// context's timer as soon as the call returns (go vet's lostcancel check
// reports a discarded cancel function).
func FetchWithTimeout(ctx context.Context, d time.Duration, work func(context.Context) string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return Fetch(ctx, work)
}

// ProcessAllUnsafe starts one goroutine per item. The number of concurrent
// goroutines, and whatever each holds (buffers, file descriptors, backend
// connections), equals the number of items the client sent (CWE-770).
func ProcessAllUnsafe(items []string, fn func(string)) {
	var wg sync.WaitGroup
	for _, it := range items {
		wg.Go(func() { fn(it) })
	}
	wg.Wait()
}

// ProcessAll runs at most limit calls of fn at a time. A buffered channel is
// the semaphore: acquiring blocks while limit tokens are out. Dispatch stops
// as soon as ctx is cancelled, and fn receives ctx so in-flight work can stop
// too. golang.org/x/sync offers the same as semaphore.Weighted and
// errgroup.Group.SetLimit.
func ProcessAll(ctx context.Context, items []string, limit int, fn func(context.Context, string)) error {
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, it := range items {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		wg.Go(func() {
			defer func() { <-sem }()
			fn(ctx, it)
		})
	}
	return nil
}
