package client

import (
	"os"
	"testing"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api/attachments"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api/bugs"

	"github.com/mozilla/OneCRL-Tools/bugzilla/api/auth"
)

func bugzillaDev() *Client {
	// A good goto is https://bugzilla-dev.allizom.org
	return NewClient(os.Getenv("BUGZILLA_DEV_HOST")).
		// Create an account in your target Bugzilla, head
		// to preferences, and generate an API key for yourself.
		WithAuth(&auth.ApiKey{os.Getenv("BUGZILLA_DEV_API_KEY")})
}

func TestVersion(t *testing.T) {
	_, err := bugzillaDev().Version()
	if err != nil {
		t.Fatal(err)
	}
}

func TestBugCreate(t *testing.T) {
	bug := &bugs.Create{
		Product:   "Core",
		Component: "Security: PSM",
		Summary:   "Tests Should Work",
		Version:   "69 Branch",
		Severity:  "normal",
		Type:      "task",
	}
	_, err := bugzillaDev().CreateBug(bug)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetBug(t *testing.T) {
	_, err := bugzillaDev().GetBug(1548159)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInvalidate(t *testing.T) {
	_, err := bugzillaDev().UpdateBug(bugs.Invalidate(1628766, "This isn't the greatest song in the world."))
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddComment(t *testing.T) {
	_, err := bugzillaDev().UpdateBug(bugs.AddComment(1628766, "No, this is just a tribute."))
	if err != nil {
		t.Fatal(err)
	}
}

// It is worth noting that this "fails" on https://bugzilla-dev.allizom.org. You will receive the following...
//
// 		Failed to fetch attachment ID 9139509 from S3: The requested key was not found
//
// However, if you browse to the target bug you will absolutely see the attachment present.
//
// If I had to guess, the code is something like...
//
//	id := db.InsertAttachment()
//	return db.GetAttachment(id).id
//
// ...and that database is failing to find an attachment it just inserted moments ago.
func TestAttachment(t *testing.T) {
	attach := &attachments.Create{
		BugId:       1628767,
		Data:        []byte("Couldn't remember the greatest song in the world."),
		FileName:    "tenacious.txt",
		Summary:     "This is just a tribute!",
		ContentType: "text/plain",
	}
	_, err := bugzillaDev().CreateAttachment(attach.AddBug(1628767))
	if err != nil {
		// @TODO change to Fatal when we figure out the above issue with Bugzilla.
		t.Log(err)
	}
}
