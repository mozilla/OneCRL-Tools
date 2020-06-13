/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package transaction // import "github.com/mozilla/OneCRL-Tools/transaction"

import (
	"sync"

	"github.com/pkg/errors"
)

// A unit of work is any function that can report whether or not it succeeded.
// Most idiomatically, this will typically be a closure which captures the state
// it is intended to mutate/rollback/close.
type Work = func() error

type Rollback = func(cause error) error

// NOOP is a convenience function for explicitly declaring that no
// particular behavior is intended for a specific unit of work.
func NOOP() error {
	return nil
}

func NOOPRollback(_ error) error {
	return nil
}

// A Transactor is any type which can move some state forward via its Commit
// function, rollback that state via the Rollback function, and (if necessary)
// destruct any resources it may be holding via the Close function.
type Transactor interface {
	Commit() error
	Rollback(cause error) error
	Close() error
}

// A Transaction is the basic unit of work that should encapsulate a single
// change in state (to the best of your ability). Idiomatically, this is usually
// a struct that contains closures, which have themselves captured the target
// pointers for state mutation.
//
// A Transaction object ITSELF is not thread safe (the setters are not in any way locked).
// However, you may wish to lock your own data that is being captured by a given transaction.
// In this case, a common pattern is to build a Transaction whose Commit is the capture
// of a lock and whose Close is the release of said lock. This may then be given as a
// step in a particular Transactions object. For example...
//
//	l := sync.Mutex{}
//	state := 0
//	err := Start().
//		Then(NewTransaction().
//			WithCommit(func() error {
//				l.Lock()
//				return nil
//			}).
//			WithClose(func() error {
//				l.Unlock()
//				return nil
//			})).
//		Then(NewTransaction().
//			WithCommit(func() error {
//				state += 1
//				return nil
//			})).
//		AutoClose(true).Commit()
//
type Transaction struct {
	commit         Work
	rollback       Rollback
	close          Work
	commitRunner   sync.Once
	rollbackRunner sync.Once
	closeRunner    sync.Once
}

func NewTransaction() *Transaction {
	return &Transaction{
		commit:   NOOP,
		rollback: NOOPRollback,
		close:    NOOP,
	}
}

// Sets the inner commit function.
// A nil input defaults to NOOP.
func (tx *Transaction) WithCommit(commit Work) *Transaction {
	if commit == nil {
		tx.commit = NOOP
	} else {
		tx.commit = commit
	}
	return tx
}

// Sets the inner rollback function.
// A nil input defaults to NOOP.
func (tx *Transaction) WithRollback(rollback Rollback) *Transaction {
	if rollback == nil {
		tx.rollback = NOOPRollback
	} else {
		tx.rollback = rollback
	}
	return tx
}

// Sets the inner close function.
// A nil input defaults to NOOP.
func (tx *Transaction) WithClose(close Work) *Transaction {
	if close == nil {
		tx.close = NOOP
	} else {
		tx.close = close
	}
	return tx
}

// Runs the configured commit function.
// This action effectively "consumes" the
// inner function.
func (tx *Transaction) Commit() (err error) {
	tx.commitRunner.Do(func() {
		err = tx.commit()
	})
	return err
}

// Runs the configured rollback function.
// This action effectively "consumes" the
// inner function.
func (tx *Transaction) Rollback(cause error) (err error) {
	tx.rollbackRunner.Do(func() {
		err = tx.rollback(cause)
	})
	return err
}

// Runs the configured close function.
// This action effectively "consumes" the
// inner function.
func (tx *Transaction) Close() (err error) {
	tx.closeRunner.Do(func() {
		err = tx.close()
	})
	return err
}

// A Transactions can encapsulate any number of individual
// Transactor interfaces and manage their execution.
//
// A Transactions is itself a Transactor, meaning that this
// relationship is recursive. That is, calling the Commit
// method of a Transactions will run all of its composited
// Transactors, of which any number of them may be themselves
// another Transactions. The same holds true for the Rollback
// and Close methods.
//
// Individual Transactors are committed in a FIFO manner relative
// to their additions via the Then method.
type Transactions struct {
	txQueue       []Transactor
	rollbackStack []Transactor
	autoClose     bool
	autoRollback  bool
}

func Start() *Transactions {
	return &Transactions{
		txQueue:       []Transactor{},
		rollbackStack: []Transactor{},
	}
}

// AutoClose sets a flag that is checked in Commit. If AutoClose is
// true, then the Transactions.Close function is deferred before
// any attempts to commit are executed.
//
// If AutoRollbackonError is set then this closure will be executed
// AFTER the rollbacks are attempted (if they are attempted).
//
// If any errors occur during closure then they will be wrapped up
// and reported by the Commit procedure itself.
func (txs *Transactions) AutoClose(should bool) *Transactions {
	txs.autoClose = should
	return txs
}

// AutoRollbackOnError sets a flag that is checked in Commit. If
// AutoRollbackOnError is true then a function is deferred that checks
// the result of Commit. If the returned error is non-nil, then
// Transactions.Rollback is called. Else, if error is nil then
// no operations is taken.
//
// If any errors occur during rollback then they will be wrapped up
// and reported by the Commit procedure itself.
func (txs *Transactions) AutoRollbackOnError(should bool) *Transactions {
	txs.autoRollback = should
	return txs
}

// Then is a fluid interface for building Transactions.
//
//	txs := transaction.Start().
//			Then(...).
//			Then(...).
//			Then(...)
//	defer txs.Close()
//	txs.Commit()
func (txs *Transactions) Then(tx Transactor) *Transactions {
	txs.txQueue = append(txs.txQueue, tx)
	return txs
}

// Commit commits all composited transactors in a FIFO manner.
// An error is returned immediately upon the failure of a single
// commit.
func (txs *Transactions) Commit() (err error) {
	errors := new(wrappedErrors)
	defer func() {
		err = errors.inner
	}()
	if txs.autoClose {
		defer func() {
			errors.add(txs.Close())
		}()
	}
	if txs.autoRollback {
		defer func() {
			if errors.inner != nil {
				cause := errors.inner
				errors.add(txs.Rollback(cause))
			}
		}()
	}
	for _, tx := range txs.txQueue {
		txs.rollbackStack = append(txs.rollbackStack, tx)
		if e := tx.Commit(); e != nil {
			errors.add(e)
			break
		}
	}
	return err
}

// Rollback rolls back any transactor which had its
// Commit method called (whether it returned and error or not).
//
// This rollback is done in a LIFO manner.
func (txs *Transactions) Rollback(cause error) error {
	err := wrappedErrors{}
	for i := len(txs.rollbackStack) - 1; i >= 0; i-- {
		err.add(txs.rollbackStack[i].Rollback(cause))
	}
	return err.inner
}

// Close closes out all composited transactors.
//
// Closing is done a FIFO manner and is done all
// composited transactors if-and-only if their
// commit function was called.
func (txs *Transactions) Close() error {
	err := wrappedErrors{}
	for i := len(txs.rollbackStack) - 1; i >= 0; i-- {
		err.add(txs.rollbackStack[i].Close())
	}
	return err.inner
}

// wrappedErrors is a helper struct to encapsulate
// the notion that we can have no error, a single
// error, or a cascade of errors.
type wrappedErrors struct {
	inner error
}

func (w *wrappedErrors) add(err error) {
	if err == nil {
		return
	} else if w.inner == nil {
		w.inner = err
	} else {
		w.inner = errors.Wrap(err, w.inner.Error())
	}
}
