package internal

import (
	"crypto/tls"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type ClientPool struct {
	ldapURL, bindDN, bindPassword string
	skipTls                       bool
	pool                          chan *ldap.Conn
}

func NewClientPool(ldapURL, bindDN, bindPassword string, skipTls bool, size int) *ClientPool {
	log.Printf("Connecting to %s bindDN %s bindPassword %s\n", ldapURL, bindDN, bindPassword)
	return &ClientPool{
		ldapURL:      ldapURL,
		bindDN:       bindDN,
		bindPassword: bindPassword,
		skipTls:      skipTls,
		pool:         make(chan *ldap.Conn, size),
	}
}

func (c *ClientPool) GetConn() (*ldap.Conn, error) {
	select {
	case conn := <-c.pool:
		return conn, nil
	default:
		return c.newConn()
	}
}

func (c *ClientPool) PutConn(conn *ldap.Conn) {
	select {
	case c.pool <- conn:
	default:
		conn.Close()
	}
}

func (c *ClientPool) newConn() (*ldap.Conn, error) {
	conn, err := ldap.DialURL(c.ldapURL)
	if err != nil {
		return nil, err
	}
	if c.skipTls && strings.HasPrefix(c.ldapURL, "ldaps://") {
		if err = conn.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if err := conn.Bind(c.bindDN, c.bindPassword); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
