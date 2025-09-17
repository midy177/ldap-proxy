package internal

import (
	"ldap-proxy/config"
	"ldap-proxy/utils"
	"log"
	"net"
	"strings"

	ldapv3 "github.com/go-ldap/ldap/v3"
	ldapserver "github.com/nmcclain/ldap"
)

func Serv(f string) {
	cfg, err := config.ParseConfig(f)
	if err != nil {
		log.Fatalf("Error parsing config: %v", err)
	}
	SetRunMode(cfg.Debug)
	sh := &ServerHandler{
		Username:    cfg.ServUser,
		Password:    cfg.ServPass,
		ClientPools: make(map[string]*LdapClient),
	}
	for _, ldapConfig := range cfg.LdapConfig {
		cp := NewClientPool(
			ldapConfig.LdapURL,
			ldapConfig.BindDN,
			ldapConfig.BindPW, ldapConfig.InsecureSkipVerify,
			ldapConfig.ClientPoolSize,
		)
		sanr := NewSwapAttributeNameRule(ldapConfig.SwapAttributeNameRule...)
		sh.ClientPools[ldapConfig.SuffixDN] = &LdapClient{
			ExtraAttributes:       ldapConfig.ExtraAttributes,
			ExcludeFilterKeys:     ldapConfig.ExcludeFilterKeys,
			RewriteOrToAnd:        ldapConfig.RewriteOrToAnd,
			SwapAttributeNameRule: sanr,
			ClientPool:            cp,
		}
	}

	s := ldapserver.NewServer()
	s.BindFunc("", sh)
	s.SearchFunc("", sh)
	log.Println("LDAP server listening on " + cfg.ServAddr)
	if err := s.ListenAndServe(cfg.ServAddr); err != nil {
		log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}

type LdapClient struct {
	ExtraAttributes       []string
	ExcludeFilterKeys     []string
	RewriteOrToAnd        bool
	SwapAttributeNameRule *SwapAttributeNameRule
	ClientPool            *ClientPool
}

type ServerHandler struct {
	Username    string
	Password    string
	ClientPools map[string]*LdapClient
}

func (s *ServerHandler) GetLdapClientBySuffixDN(dn string) *LdapClient {
	for suffix, ldapClient := range s.ClientPools {
		if strings.HasSuffix(dn, suffix) {
			// 命中
			log.Printf("Get ClientPool By Suffix DN: %s", dn)
			return ldapClient
		}
	}
	log.Printf("Can't get ClientPool By Suffix DN: %s", dn)
	return nil
}

// Bind 接口：验证简单用户名/密码
func (s *ServerHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldapserver.LDAPResultCode, error) {
	if bindDN == s.Username && bindSimplePw == s.Password {
		log.Printf("LDAP User %s is authorized", s.Username)
		return ldapserver.LDAPResultSuccess, nil
	}
	// 1) 取上游连接
	ldapClient := s.GetLdapClientBySuffixDN(bindDN)
	if ldapClient == nil {
		return ldapserver.LDAPResultInvalidCredentials, nil
	}
	cc, err := ldapClient.ClientPool.GetConn()
	if err != nil {
		log.Printf("Error getting client connection: %v", err)
		return ldapserver.LDAPResultInvalidCredentials, err
	}
	// 归还到连接池
	defer ldapClient.ClientPool.PutConn(cc)

	err = cc.Bind(bindDN, bindSimplePw)
	if err != nil {
		log.Printf("Bind request for user %s failed", bindDN)
		return ldapserver.LDAPResultInvalidCredentials, err
	}
	log.Printf("User %s is authorized", bindDN)
	return ldapserver.LDAPResultSuccess, nil
}

// Search 接口：把请求转发到上游 LDAP（使用 go-ldap/ldap/v3 客户端）
func (s *ServerHandler) Search(boundDN string, req ldapserver.SearchRequest, conn net.Conn) (ldapserver.ServerSearchResult, error) {
	// 1) 取上游连接
	ldapClient := s.GetLdapClientBySuffixDN(req.BaseDN)
	if ldapClient == nil {
		return ldapserver.ServerSearchResult{
			ResultCode: ldapserver.LDAPResultInvalidCredentials,
		}, nil
	}

	cc, err := ldapClient.ClientPool.GetConn()
	if err != nil {
		log.Printf("Error getting client connection: %v\n", err)
		return ldapserver.ServerSearchResult{
			ResultCode: ldapserver.LDAPResultOperationsError,
		}, err
	}
	// 归还到连接池
	defer ldapClient.ClientPool.PutConn(cc)
	err = ldapClient.ClientPool.BindCredentials(cc)
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
	case 3: // Children
		v3scope = ldapv3.ScopeChildren
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
	for _, attr := range ldapClient.ExtraAttributes {
		attrs = append(attrs, attr)
	}
	filter := dropAttrsFromFilter(req.Filter, ldapClient.ExcludeFilterKeys)
	if ldapClient.RewriteOrToAnd {
		filter = rewriteOrToAnd(filter)
	}
	if GetRunMode() {
		log.Printf("BaseDN %s Source Filter %s Rewrite Filter %s with %v attributes", req.BaseDN, req.Filter, filter, attrs)
	}

	// 3) 构造 v3 的 SearchRequest
	v3req := ldapv3.NewSearchRequest(
		req.BaseDN, // base DN
		v3scope,    // scope
		v3deref,    // deref
		sizeLimit,  // size limit
		timeLimit,  // time limit
		typesOnly,  // types only
		filter,     // filter 字符串
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
	if GetRunMode() {
		log.Printf("Search Result Entries lens: %v\n", len(resp.Entries))
	}
	for _, e := range resp.Entries {
		entry := &ldapserver.Entry{
			DN: e.DN,
		}
		attrsLength := len(e.Attributes)
		for _, a := range e.Attributes {
			if name := ldapClient.SwapAttributeNameRule.AfterSwapName(a.Name); name != "" && attrsLength != 1 {
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
	}

	return out, nil
}

func dropAttrsFromFilter(filter string, dropAttrs []string) string {
	fromFilter, err := utils.DropAttrsFromFilter(filter, dropAttrs)
	if err != nil {
		log.Printf("Drop Attributes Error: %v\n", err)
		return filter
	}
	return fromFilter
}

func rewriteOrToAnd(filter string) string {
	out, err := utils.RewriteOrToAnd(filter)
	if err != nil {
		log.Printf("Rewrite Error: %v\n", err)
		return filter
	}
	return out
}
