package obsDiffCCADB

import "testing"

var mustMatch = []string{` Mozilla`,
	// The leading, trailing, and consecutive spaces rules.
	`Mozilla `, `Mozilla  Mozilla`, `Mozilla   Mozilla`, ` Mozilla  Mozilla`, `Mozilla  Mozilla `,
	// The containment of special characters.
	`__,__`, `__+__`, `__=__`, `__"__`, `__<__`, `__>__`, `__#__`, `__;__`, `__\__`,
	// Two rules appyling at the same time, containing and trailing and leading spaces.
	`__,__ `, `__+__ `, `__=__ `, `__"__ `, `__<__ `, `__>__ `, `__#__ `, `__;__ `,
	` __,__`, ` __+__`, ` __=__`, ` __"__`, ` __<__`, ` __>__`, ` __#__`, ` __;__`}

func TestDNRegexPositive(t *testing.T) {
	for _, s := range mustMatch {
		if !dnEscapeRegex.MatchString(s) {
			t.Errorf(`Distinguished Name escape quotation rule failed to match: "%v"`, s)
		}
	}
}

var mustNotMatch = []string{"Mozilla",
	"Mozilla Foundation",
	"An Open and Free Internet",
	"moz://a",
	"Mega Huge Inc (copyright 2005)",
	""}

func TestDNRegexNegative(t *testing.T) {
	for _, s := range mustNotMatch {
		if dnEscapeRegex.MatchString(s) {
			t.Errorf(`Distinguished Name escape quotation rule unexpectedly matched: "%v"`, s)
		}
	}
}

var escapeTest = map[string]string{`Mozilla, Foundation`: `"Mozilla, Foundation"`,
	`Mozilla+ Foundation`: `"Mozilla+ Foundation"`,
	`Mozilla= Foundation`: `"Mozilla= Foundation"`,
	`Mozilla" Foundation`: `"Mozilla\" Foundation"`,
	`Mozilla< Foundation`: `"Mozilla< Foundation"`,
	`Mozilla> Foundation`: `"Mozilla> Foundation"`,
	`Mozilla# Foundation`: `"Mozilla# Foundation"`,
	`Mozilla; Foundation`: `"Mozilla; Foundation"`,
	`Mozilla\ Foundation`: `"Mozilla\ Foundation"`,
	` Mozilla Foundation`: `" Mozilla Foundation"`,
	`Mozilla Foundation `: `"Mozilla Foundation "`,
	`Mozilla  Foundation`: `"Mozilla  Foundation"`,
}

func TestRDNEscape(t *testing.T) {
	for in, want := range escapeTest {
		got := FmtRDN(in)
		if got != want {
			t.Errorf("Failed to escape RDN. Got %v wanted %v\n", got, want)
		}
	}
}
