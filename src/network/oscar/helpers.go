package oscar

import "math/rand"

func OSCARIncrementServerSequence(context *OSCARContext) {
	if context.ServerSequence != 65535 {
		context.ServerSequence++
	} else {
		context.ServerSequence = 0
	}
}

func OSCARClearServerSequence(context *OSCARContext) {
	context.ServerSequence = uint16(rand.Intn(0xFFFF))
}
