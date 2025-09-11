package internal

import (
	"log"
	"net"
	"regexp"
	"strings"

	ldapv3 "github.com/go-ldap/ldap/v3"
	ldapserver "github.com/nmcclain/ldap"
)

func Serv(cp *ClientPool, sanr *SwapAttributeNameRule, user, pass, attrs, addr string) {
	s := ldapserver.NewServer()
	h := newServer(cp, sanr, user, pass, attrs)
	s.BindFunc("", h)
	s.SearchFunc("", h)
	log.Println("LDAP server listening on " + addr)
	if err := s.ListenAndServe(addr); err != nil {
		log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}

type Server struct {
	Username    string
	Password    string
	AppendAttrs []string
	ClientPool  *ClientPool
	SANR        *SwapAttributeNameRule
}

func newServer(cp *ClientPool, sanr *SwapAttributeNameRule, user, pass, appendAttrs string) *Server {
	log.Printf("LDAP servUser %s servPass %s\n", user, pass)
	appendAttrs = strings.TrimSpace(appendAttrs)
	attrs := strings.Split(appendAttrs, ",")
	log.Printf("append Attributes %v\n", attrs)
	return &Server{
		Username:    user,
		Password:    pass,
		AppendAttrs: attrs,
		ClientPool:  cp,
		SANR:        sanr,
	}
}

// Bind 接口：验证简单用户名/密码
func (s *Server) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldapserver.LDAPResultCode, error) {
	if bindDN == s.Username && bindSimplePw == s.Password {
		log.Printf("LDAP User %s is authorized", s.Username)
		return ldapserver.LDAPResultSuccess, nil
	}
	// 1) 取上游连接
	cc, err := s.ClientPool.GetConn()
	if err != nil {
		log.Printf("Error getting client connection: %v", err)
		return ldapserver.LDAPResultInvalidCredentials, err
	}
	// 归还到连接池
	defer s.ClientPool.PutConn(cc)

	err = cc.Bind(bindDN, bindSimplePw)
	if err != nil {
		log.Printf("Bind request for user %s failed", bindDN)
		return ldapserver.LDAPResultInvalidCredentials, err
	}
	log.Printf("User %s is authorized", bindDN)
	return ldapserver.LDAPResultSuccess, nil
}

// Search 接口：把请求转发到上游 LDAP（使用 go-ldap/ldap/v3 客户端）
func (s *Server) Search(boundDN string, req ldapserver.SearchRequest, conn net.Conn) (ldapserver.ServerSearchResult, error) {
	// 1) 取上游连接
	cc, err := s.ClientPool.GetConn()
	if err != nil {
		log.Printf("Error getting client connection: %v\n", err)
		return ldapserver.ServerSearchResult{
			ResultCode: ldapserver.LDAPResultOperationsError,
		}, err
	}
	// 归还到连接池
	defer s.ClientPool.PutConn(cc)
	err = s.ClientPool.BindCredentials(cc)
	if err != nil {
		log.Printf("Bind request for deafult user failed")
		return ldapserver.ServerSearchResult{
			ResultCode: ldapserver.LDAPResultInvalidCredentials,
		}, err
	}

	// 2) 将 scope/deref/limit 等从 server 映射到 v3
	scope := req.Scope
	var v3scope int
	switch scope {
	case 0: // BaseObject
		v3scope = ldapv3.ScopeBaseObject
	case 1: // SingleLevel
		v3scope = ldapv3.ScopeSingleLevel
	default: // WholeSubtree
		v3scope = ldapv3.ScopeWholeSubtree
	}

	deref := req.DerefAliases
	var v3deref int
	switch deref {
	case 0:
		v3deref = ldapv3.NeverDerefAliases
	case 1:
		v3deref = ldapv3.DerefInSearching
	case 2:
		v3deref = ldapv3.DerefFindingBaseObj
	default:
		v3deref = ldapv3.DerefAlways
	}

	sizeLimit := req.SizeLimit
	timeLimit := req.TimeLimit
	typesOnly := req.TypesOnly
	attrs := req.Attributes
	for _, attr := range s.AppendAttrs {
		attrs = append(attrs, attr)
	}

	if GetRunMode() {
		log.Printf("BaseDN %s Filter %s with %v attributes", req.BaseDN, req.Filter, attrs)
	}

	// 3) 构造 v3 的 SearchRequest
	v3req := ldapv3.NewSearchRequest(
		req.BaseDN, // base DN
		v3scope,    // scope
		v3deref,    // deref
		sizeLimit,  // size limit
		timeLimit,  // time limit
		typesOnly,  // types only
		req.Filter, // filter 字符串
		attrs,      // attributes
		nil,        // controls
	)

	// 4) 执行上游查询
	resp, err := cc.Search(v3req)
	if err != nil {
		log.Printf("Search Error: %v\n", err)
		log.Println(req.BaseDN)
		return ldapserver.ServerSearchResult{
			ResultCode: ldapserver.LDAPResultOperationsError,
		}, err
	}

	// 5) 把 v3 的结果映射回 server 的返回类型
	out := ldapserver.ServerSearchResult{
		Entries:    make([]*ldapserver.Entry, 0, len(resp.Entries)),
		Referrals:  resp.Referrals,
		ResultCode: ldapserver.LDAPResultSuccess,
	}
	// 跳过 LDAP bug
	re := regexp.MustCompile(`^\(&\(objectClass=posixAccount\)\(\|(uid=[^()]+|mobile=[^()]+|mail=[^()]+|sAMAccountName=[^()]+)+\)\)$`)
	onlyOne := re.MatchString(req.Filter)
	for _, e := range resp.Entries {
		entry := &ldapserver.Entry{
			DN: e.DN,
		}
		for _, a := range e.Attributes {
			if name := s.SANR.AfterSwapName(a.Name); name != "" {
				entry.Attributes = append(entry.Attributes, &ldapserver.EntryAttribute{
					Name:   name,
					Values: a.Values,
				})
			} else {
				entry.Attributes = append(entry.Attributes, &ldapserver.EntryAttribute{
					Name:   a.Name,
					Values: a.Values,
				})
			}
		}
		out.Entries = append(out.Entries, entry)
		if onlyOne {
			log.Printf("match only one rule")
			break
		}
	}

	if GetRunMode() {
		log.Printf("Search Result Entries lens: %v\n", len(out.Entries))
	}
	return out, nil
}
