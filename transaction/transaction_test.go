/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package transaction

import (
	"sync"
	"testing"

	"github.com/pkg/errors"
)

func TestNOOPTransaction(t *testing.T) {
	tx := NewTransaction()
	if err := tx.Commit(); err != nil {
		t.Error(err)
	}
	if err := tx.Rollback(nil); err != nil {
		t.Error(err)
	}
	if err := tx.Close(); err != nil {
		t.Error(err)
	}
}

func TestTransactionCommit(t *testing.T) {
	state := 0
	tx := NewTransaction().WithCommit(func() error {
		state += 1
		return nil
	})
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got := state
	want := 1
	if got != want {
		t.Fatalf("The commit function failed to move state forward: got '%d', want '%d", got, want)
	}
}

func TestTransactionCommitNOOP(t *testing.T) {
	state := 0
	tx := NewTransaction().WithCommit(func() error {
		state += 1
		return nil
	})
	tx.WithCommit(nil)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got := state
	want := 0
	if got != want {
		t.Fatalf("The commit function failed to be set to a NOOP: got '%d', want '%d", got, want)
	}
}

func TestCommitConsumption(t *testing.T) {
	state := 0
	tx := NewTransaction().WithCommit(func() error {
		state += 1
		return nil
	})
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got := state
	want := 1
	if got != want {
		t.Fatalf("The commit function failed to move state forward: got '%d', want '%d", got, want)
	}
	// Run it again to assert the NOOP.
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got = state
	if got != want {
		t.Fatalf("The commit function failed to be consumed into a NOOP: got '%d', want '%d", got, want)
	}
}

func TestTransactionRollback(t *testing.T) {
	state := 0
	tx := NewTransaction().
		WithCommit(func() error {
			state += 1
			return nil
		}).
		WithRollback(func(_ error) error {
			state -= 1
			return nil
		})
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got := state
	want := 1
	if got != want {
		t.Fatalf("The commit function failed to move state forward: got '%d', want '%d", got, want)
	}
	if err := tx.Rollback(nil); err != nil {
		t.Fatal(err)
	}
	got = state
	want = 0
	if got != want {
		t.Fatalf("The rollback function failed to move state back: got '%d', want '%d", got, want)
	}
}

func TestTransactionRollbackNOOP(t *testing.T) {
	state := 0
	tx := NewTransaction().
		WithCommit(func() error {
			state += 1
			return nil
		}).
		WithRollback(func(_ error) error {
			state -= 1
			return nil
		})
	tx.WithRollback(nil)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got := state
	want := 1
	if got != want {
		t.Fatalf("The commit function failed to move state forward: got '%d', want '%d", got, want)
	}
	if err := tx.Rollback(nil); err != nil {
		t.Fatal(err)
	}
	got = state
	want = 1
	if got != want {
		t.Fatalf("The rollback function failed to be set to a NOOP: got '%d', want '%d", got, want)
	}
}

func TestTransactionRollbackConsumption(t *testing.T) {
	state := 0
	tx := NewTransaction().
		WithCommit(func() error {
			state += 1
			return nil
		}).
		WithRollback(func(_ error) error {
			state -= 1
			return nil
		})
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got := state
	want := 1
	if got != want {
		t.Fatalf("The commit function failed to move state forward: got '%d', want '%d", got, want)
	}
	if err := tx.Rollback(nil); err != nil {
		t.Fatal(err)
	}
	got = state
	want = 0
	if got != want {
		t.Fatalf("The rollback function failed to move state back: got '%d', want '%d", got, want)
	}
	// Run it again to assert the NOOP.
	if err := tx.Rollback(nil); err != nil {
		t.Fatal(err)
	}
	got = state
	if got != want {
		t.Fatalf("The rollback function failed to move state back: got '%d', want '%d", got, want)
	}
}

func TestTransactionClose(t *testing.T) {
	// A Close test can really look just like a Commit test as they're both
	// functions that change some state and need to consumed into a NOOP.
	state := 0
	tx := NewTransaction().WithClose(func() error {
		state += 1
		return nil
	})
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	got := state
	want := 1
	if got != want {
		t.Fatalf("The close function failed to take affect: got '%d', want '%d", got, want)
	}
}
func TestTransactionCloseNOOP(t *testing.T) {
	// A Close test can really look just like a Commit test as they're both
	// functions that change some state and need to consumed into a NOOP.
	state := 0
	tx := NewTransaction().WithClose(func() error {
		state += 1
		return nil
	})
	tx.WithClose(nil)
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	got := state
	want := 0
	if got != want {
		t.Fatalf("The close function failed to be set to NOOP: got '%d', want '%d", got, want)
	}
}

func TestCloseConsumption(t *testing.T) {
	state := 0
	tx := NewTransaction().WithClose(func() error {
		state += 1
		return nil
	})
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	got := state
	want := 1
	if got != want {
		t.Fatalf("The close function failed to take affect: got '%d', want '%d", got, want)
	}
	// Run it again to assert the NOOP.
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	got = state
	if got != want {
		t.Fatalf("The close function failed to be consumed into a NOOP: got '%d', want '%d", got, want)
	}
}

func TestTransactions(t *testing.T) {
	state1 := 0
	state2 := 10
	txs := Start().
		Then(NewTransaction().
			WithCommit(func() error {
				state1 += 1
				return nil
			}).
			WithRollback(func(_ error) error {
				state1 -= 1
				return nil
			}).
			WithClose(func() error {
				state1 += 2
				return nil
			})).
		Then(NewTransaction().
			WithCommit(func() error {
				state2 *= 10
				return nil
			}).
			WithRollback(func(_ error) error {
				state2 /= 10
				return nil
			}).
			WithClose(func() error {
				state2 *= 100
				return nil
			}))
	if err := txs.Commit(); err != nil {
		t.Fatal(err)
	}
	if state1 != 1 {
		t.Errorf("failed to commit tx 1 forwarded: got '%d', want '%d'", state1, 1)
	}
	if state2 != 100 {
		t.Errorf("failed to commit tx 2 forwarded: got '%d', want '%d'", state2, 100)
	}
	if err := txs.Rollback(nil); err != nil {
		t.Fatal(err)
	}
	if state1 != 0 {
		t.Errorf("failed to rollback tx 1: got '%d', want '%d'", state1, 0)
	}
	if state2 != 10 {
		t.Errorf("failed to rollback tx 2: got '%d', want '%d'", state2, 10)
	}
	if err := txs.Close(); err != nil {
		t.Fatal(err)
	}
	if state1 != 2 {
		t.Errorf("failed to close tx 1: got '%d', want '%d'", state1, 2)
	}
	if state2 != 1000 {
		t.Errorf("failed to close tx 2: got '%d', want '%d'", state2, 1000)
	}
}

func TestTransactionsWithErrs(t *testing.T) {
	state1 := 0
	state2 := 10
	state3 := 2
	txs := Start().
		Then(NewTransaction().
			WithCommit(func() error {
				state1 += 1
				return nil
			}).
			WithRollback(func(_ error) error {
				state1 -= 1
				return nil
			}).
			WithClose(func() error {
				state1 += 2
				return nil
			})).
		Then(NewTransaction().
			WithCommit(func() error {
				state2 *= 10
				return nil
			}).
			WithRollback(func(_ error) error {
				state2 /= 10
				return errors.New("...there was supposed to be an Earth shattering KABOOM!")
			}).
			WithClose(func() error {
				state2 *= 100
				return errors.New("I claim this planet in the name of Mars!")
			})).
		Then(NewTransaction().
			WithCommit(func() error {
				state3 <<= 1
				return errors.New("Where's the kaboom?")
			}).
			WithRollback(func(_ error) error {
				state3 >>= 1
				return nil
			}).
			WithClose(func() error {
				state3 <<= 2
				return errors.New("Isn't that lovely?")
			}))
	if err := txs.Commit(); err == nil {
		t.Fatal("An error was expected from the final transaction commit, but got nothing")
	}
	if state1 != 1 {
		t.Errorf("failed to commit tx 1 forwarded: got '%d', want '%d'", state1, 1)
	}
	if state2 != 100 {
		t.Errorf("failed to commit tx 2 forwarded: got '%d', want '%d'", state2, 100)
	}
	if state3 != 4 {
		t.Errorf("failed to commit tx 3 forwarded: got '%d', want '%d'", state3, 4)
	}
	if err := txs.Rollback(nil); err == nil {
		t.Fatal("An error was expected from the final transaction rollback, but got nothing")
	}
	if state1 != 0 {
		t.Errorf("failed to rollback tx 1: got '%d', want '%d'", state1, 0)
	}
	if state2 != 10 {
		t.Errorf("failed to rollback tx 2: got '%d', want '%d'", state2, 10)
	}
	if state3 != 2 {
		t.Errorf("failed to rollback tx 3: got '%d', want '%d'", state3, 2)
	}
	if err := txs.Close(); err == nil {
		t.Fatal("An error was expected from the final transaction close, but got nothing")
	}
	if state1 != 2 {
		t.Errorf("failed to close tx 1: got '%d', want '%d'", state1, 2)
	}
	if state2 != 1000 {
		t.Errorf("failed to close tx 2: got '%d', want '%d'", state2, 1000)
	}
	if state3 != 8 {
		t.Errorf("failed to close tx 3: got '%d', want '%d'", state3, 8)
	}
}

func TestTransactionsAuto(t *testing.T) {
	state1 := 0
	state2 := 10
	txs := Start().
		Then(NewTransaction().
			WithCommit(func() error {
				state1 += 1
				return nil
			}).
			WithRollback(func(_ error) error {
				state1 -= 1
				return nil
			}).
			WithClose(func() error {
				state1 += 2
				return nil
			})).
		Then(NewTransaction().
			WithCommit(func() error {
				state2 *= 10
				return errors.New("")
			}).
			WithRollback(func(_ error) error {
				state2 /= 10
				return nil
			}).
			WithClose(func() error {
				state2 *= 100
				return nil
			})).AutoClose(true).AutoRollbackOnError(true)
	if err := txs.Commit(); err == nil {
		t.Fatal("expected an error during commit")
	}
	if state1 != 2 {
		t.Errorf("got '%d', want '%d'", state1, 2)
	}
	if state2 != 1000 {
		t.Errorf("got '%d', want '%d'", state2, 1000)
	}
}

// NOTE: please run this with `go test -race .` in order
// to get an accurate read on this test.
func TestUserLocks(t *testing.T) {
	l := sync.Mutex{}
	wg := sync.WaitGroup{}
	state := 0
	wg.Add(2)
	tx1 := Start().
		Then(NewTransaction().
			WithCommit(func() error {
				l.Lock()
				return nil
			}).
			WithClose(func() error {
				wg.Done()
				l.Unlock()
				return nil
			})).
		Then(NewTransaction().WithCommit(func() error {
			state += 1
			return nil
		})).AutoClose(true)
	tx2 := Start().
		Then(NewTransaction().
			WithCommit(func() error {
				l.Lock()
				return nil
			}).
			WithClose(func() error {
				wg.Done()
				l.Unlock()
				return nil
			})).
		Then(NewTransaction().WithCommit(func() error {
			state += 2
			return nil
		})).AutoClose(true)
	go tx1.Commit()
	go tx2.Commit()
	wg.Wait()
	if state != 3 {
		t.Fatalf("got '%d', want '%d'", state, 3)
	}
}

func TestTransactionsAutoErrorAggregation(t *testing.T) {
	state := 0
	err := Start().Then(NewTransaction().WithCommit(func() error {
		state += 1
		return errors.New("commit")
	}).WithClose(func() error {
		state += 2
		return errors.New("close")
	}).WithRollback(func(_ error) error {
		state += 4
		return errors.New("rollback")
	})).AutoClose(true).AutoRollbackOnError(true).Commit()
	if err == nil {
		t.Fatal("expected an error, got nothing")
	}
	if state != 7 {
		t.Errorf("got '%d', want '%d'", state, 7)
	}
	got := err.Error()
	want := "commit: rollback: close"
	if got != want {
		t.Fatalf("expected an aggregation of errors, got: '%s', want '%s", got, want)
	}
}

func TestNoRollback(t *testing.T) {
	state := 0
	err := Start().Then(NewTransaction().WithCommit(func() error {
		state += 1
		return nil
	}).WithRollback(func(_ error) error {
		state += 1
		return nil
	})).AutoClose(true).AutoRollbackOnError(true).Commit()
	if err != nil {
		t.Fatal(err)
	}
	if state != 1 {
		t.Fatalf("got %d, want 1", state)
	}
}

func TestCausePropagation(t *testing.T) {
	state1 := 0
	state2 := 10
	txs := Start().
		Then(NewTransaction().
			WithCommit(func() error {
				state1 += 1
				return nil
			}).
			WithRollback(func(cause error) error {
				state1 -= 1
				if cause == nil || cause.Error() != "kaboom" {
					t.Fatalf("unexpected error value %v", cause)
				}
				return nil
			}).
			WithClose(func() error {
				state1 += 2
				return nil
			})).
		Then(NewTransaction().
			WithCommit(func() error {
				state2 *= 10
				return errors.New("kaboom")
			}).
			WithRollback(func(cause error) error {
				state2 /= 10
				if cause == nil || cause.Error() != "kaboom" {
					t.Fatalf("unexpected error value %v", cause)
				}
				return nil
			}).
			WithClose(func() error {
				state2 *= 100
				return nil
			})).AutoClose(true).AutoRollbackOnError(true)
	if err := txs.Commit(); err == nil {
		t.Fatal("expected an error during commit")
	}
	if state1 != 2 {
		t.Errorf("got '%d', want '%d'", state1, 2)
	}
	if state2 != 1000 {
		t.Errorf("got '%d', want '%d'", state2, 1000)
	}
}
