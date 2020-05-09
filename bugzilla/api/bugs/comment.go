package bugs

func AddComment(bug int, comment string) *Update {
	return &Update{Id: bug, Comment: &Comment{Body: comment}}
}
