package transaction // import "github.com/mozilla/OneCRL-Tools/transaction"

import (
	"github.com/pkg/errors"
)

// A unit of work is any function that can report whether or not it succeeded.
// Most idiomatically, this will typically be a closure which captures the state
// it is intended to mutate/rollback/close.
type Work = func() error

// NOOP is a convenience function for explicitly declaring that no
// particular behavior is intended for a specific unit of work.
func NOOP() error {
	return nil
}

// A Transactor is any type which can move some state forward via its Commit
// function, rollback that state via the Rollback function, and (if necessary)
// destruct any resources it may be holding via the Close function.
type Transactor interface {
	Commit() error
	Rollback() error
	Close() error
}

// A Transaction is the basic unit of work that should encapsulate a single
// change in state (to the best of your ability). Idiomatically, this is usually
// a struct that contains closures, which have themselves captured the target
// pointers for state mutation.
type Transaction struct {
	commit   Work
	rollback Work
	close    Work
}

func NewTransaction() *Transaction {
	return &Transaction{
		commit:   NOOP,
		rollback: NOOP,
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
func (tx *Transaction) WithRollback(rollback Work) *Transaction {
	if rollback == nil {
		tx.rollback = NOOP
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
// inner function by setting it to a NOOP.
func (tx *Transaction) Commit() error {
	defer func() { tx.commit = NOOP }()
	return tx.commit()
}

// Runs the configured rollback function.
// This action effectively "consumes" the
// inner function by setting it to a NOOP.
func (tx *Transaction) Rollback() error {
	defer func() { tx.rollback = NOOP }()
	return tx.rollback()
}

// Runs the configured close function.
// This action effectively "consumes" the
// inner function by setting it to a NOOP.
func (tx *Transaction) Close() error {
	defer func() { tx.close = NOOP }()
	return tx.close()
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
}

func Start() *Transactions {
	return &Transactions{
		txQueue:       []Transactor{},
		rollbackStack: []Transactor{},
	}
}

// Then is a fluid interface for building Transactions.
//
//	txs := transaction.Start().
//			Then(...).
//			Then(...).
//			Then(...)
//	defer txs.Close()
//	txs.Commit()
func (t *Transactions) Then(tx Transactor) *Transactions {
	t.txQueue = append(t.txQueue, tx)
	return t
}

// Commit commits all composited transactors in a FIFO manner.
// An error is returned immediately upon the failure of a single
// commit.
func (t *Transactions) Commit() error {
	for _, tx := range t.txQueue {
		t.rollbackStack = append(t.rollbackStack, tx)
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Rollback rolls back any transactor which had its
// Commit method called (whether it returned and error or not).
//
// This rollback is done in a LIFO manner.
func (t *Transactions) Rollback() error {
	err := wrappedErrors{}
	for i := len(t.rollbackStack) - 1; i >= 0; i-- {
		err.add(t.rollbackStack[i].Rollback())
	}
	return err.inner
}

// Close closes out all composited transactors.
//
// Closing is done a FIFO manner and is done all
// composited transactors, regardless if their
// Commit or Rollback functions were called.
func (t *Transactions) Close() error {
	err := wrappedErrors{}
	for _, tx := range t.txQueue {
		err.add(tx.Close())
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
