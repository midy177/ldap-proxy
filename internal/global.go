package internal

var debug bool

func GetRunMode() bool {
	return debug
}

func SetRunMode(d bool) {
	debug = d
}
