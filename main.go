package main

import (
	"flag"
	"ldap-proxy/internal"
)

func main() {
	config := flag.String("config", "config.yaml", "Configuration file")
	flag.Parse()
	internal.Serv(*config)
}
