package network

import (
	"chimera/utility/tcp"
)

type Client struct {
	Connection    tcp.TcpConnection
	ClientInfo    Details
	ClientAccount Account
	ClientUser    User
}

type Details struct {
	Messenger string
	Build     string
	Protocol  string
}

type Account struct {
	UIN         int
	DisplayName string
	Mail        string
	Password    string
}

type User struct {
	UIN             int
	AvatarBlob      string
	AvatarImageType string
	StatusMessage   string
	LastLogin       int64
	SignupDate      int
}

type Contact struct {
	SenderUIN int
	FriendUIN int
	Reason    string
}

type OfflineMessage struct {
	SenderUIN      int
	RecvUIN        int
	MessageDate    int
	MessageContent string
}

type Meta struct {
	UIN         int
	UsageFlag   int
	AccountFlag int
}

var Clients []*Client

// Meta
const (
	UsageFlag_Normal    = 0x0001
	UsageFlag_Donator   = 0x0002
	UsageFlag_Beta      = 0x0003
	UsageFlag_Alpha     = 0x0004
	UsageFlag_Developer = 0x0005
)

const (
	AccountFlag_Normal   = 0x0001
	AccountFlag_Disabled = 0x0002
	AccountFlag_Banned   = 0x0003
	AccountFlag_Underage = 0x0004
	AccountFlag_Timeout  = 0x0005
)
