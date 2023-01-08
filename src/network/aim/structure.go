package aim

type AIMContext struct {
	ServerSequence uint16
	ClientSequence uint16
	Challenge	   []byte
	BOSCookie	   []byte
	UIN			   int
}

var clientContexts []*AIMContext
