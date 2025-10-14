package harden

type HardeningCheck struct {
	Name string
	Fn   func() []HardeningResult
}

type HardeningResult struct {
	Secure         bool
	Message        string
	Recommendation string
}
