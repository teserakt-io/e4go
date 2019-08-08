package e4common

// Command is a command sent by C2 to a client.
type Command int

// ...
const (
	RemoveTopic Command = iota
	ResetTopics
	SetIDKey
	SetTopicKey
	RemovePubKey
	ResetPubKeys
	SetPubKey
)

// ToByte converts a command into its byte representation
func (c *Command) ToByte() byte {
	switch *c {
	case RemoveTopic:
		return 0
	case ResetTopics:
		return 1
	case SetIDKey:
		return 2
	case SetTopicKey:
		return 3
	case RemovePubKey:
		return 4
	case ResetPubKeys:
		return 5
	case SetPubKey:
		return 6
	}
	return 255
}

// ToString converts a command into its string representation.
func (c *Command) ToString() string {

	switch *c {
	case RemoveTopic:
		return "RemoveTopic"
	case ResetTopics:
		return "ResetTopics"
	case SetIDKey:
		return "SetIDKey"
	case SetTopicKey:
		return "SetTopicKey"
	case RemovePubKey:
		return "RemovePubKey"
	case ResetPubKeys:
		return "ResetPubKeys"
	case SetPubKey:
		return "SetPubKey"
	}
	return ""
}
