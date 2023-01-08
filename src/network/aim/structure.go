package aim

type AIMContext struct {
	ServerSequence uint16
	ClientSequence uint16
	Nonce		   []byte
}
