package oscar

func LaunchOSCAR() {
	// cheapo method of launching multiple listeners ig
	go ListenBUCP() // Port 5190
	go ListenBOS()  // Port 5191
}
