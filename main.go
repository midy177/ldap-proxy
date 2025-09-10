package main

import (
	"flag"
	"ldap-proxy/internal"
)

func main() {
	ldapURL := flag.String("ldapURL", "ldap://ldap.amazonaws.com", "LDAP URL")
	bindDN := flag.String("bindDN", "", "LDAP bind DN")
	bindPW := flag.String("bindPW", "", "LDAP bind PW")
	skipTls := flag.Bool("skipTls", false, "Skip LDAP TLS verification")
	poolSize := flag.Int("poolSize", 10, "LDAP pool size")
	sanrStr := flag.String("sanr", "", "LDAP swap attribute name rule, example:name1<->name2;name5<->name6")
	servUser := flag.String("servUser", "admin", "LDAP server username")
	servPass := flag.String("servPass", "admin", "LDAP server password")
	servAddr := flag.String("servAddr", "0.0.0.0:389", "LDAP server address")
	flag.Parse()
	cp := internal.NewClientPool(
		*ldapURL,
		*bindDN,
		*bindPW, *skipTls,
		*poolSize,
	)
	sanr := internal.NewSwapAttributeNameRule(*sanrStr)
	internal.Serv(cp, sanr, *servUser, *servPass, *servAddr)
}
