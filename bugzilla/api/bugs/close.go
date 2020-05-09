package bugs

// Invalidate set the status of the target bug to RESOLVED
// with the resolution INVALID and posts the provided comment
// as an explanation for the resolution.
func Invalidate(bug int, comment string) *Update {
	return &Update{Id: bug, Status: "RESOLVED", Resolution: "INVALID", Comment: &Comment{Body: comment}}
}
