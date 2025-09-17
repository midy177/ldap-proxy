package utils

import (
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// DropAttrsFromFilter 丢弃过滤器中指定属性（大小写不敏感）。
// 支持等值(=)、子串(substrings)、>=、<=、~=、存在(attr=*) 等常见节点。
// 注意：如果删除后整体表达式为空，返回 "(objectClass=*)" 作为兜底（你也可以改为返回原始过滤器或报错）。
func DropAttrsFromFilter(filter string, dropAttrs []string) (string, error) {
	pkt, err := ldap.CompileFilter(filter)
	if err != nil {
		return "", fmt.Errorf("compile filter: %w", err)
	}
	// 构造黑名单集合（小写）
	drop := make(map[string]struct{}, len(dropAttrs))
	for _, a := range dropAttrs {
		drop[strings.ToLower(a)] = struct{}{}
	}

	keep := pruneAndDrop(pkt, drop)
	if !keep {
		// 全被删空，给一个最宽松但合法的兜底
		return "(objectClass=*)", nil
	}
	out, err := ldap.DecompileFilter(pkt)
	if err != nil {
		return "", fmt.Errorf("decompile filter: %w", err)
	}
	return out, nil
}

// 递归修剪：返回 true 表示该节点仍然有效；false 表示应删除该节点。
func pruneAndDrop(p *ber.Packet, drop map[string]struct{}) bool {
	if p == nil {
		return false
	}
	if p.ClassType == ber.ClassContext {
		switch int(p.Tag) {
		case 0: // AND
			children := make([]*ber.Packet, 0, len(p.Children))
			for _, c := range p.Children {
				if pruneAndDrop(c, drop) {
					children = append(children, c)
				}
			}
			switch len(children) {
			case 0:
				return false // 整个 AND 删除
			case 1:
				*p = *children[0] // 单子节点，提升
				return true
			default:
				p.Children = children
				return true
			}

		case 1: // OR
			children := make([]*ber.Packet, 0, len(p.Children))
			for _, c := range p.Children {
				if pruneAndDrop(c, drop) {
					children = append(children, c)
				}
			}
			switch len(children) {
			case 0:
				return false
			case 1:
				*p = *children[0]
				return true
			default:
				p.Children = children
				return true
			}

		case 2: // NOT
			if len(p.Children) == 0 {
				return false
			}
			if !pruneAndDrop(p.Children[0], drop) {
				// NOT 的子节点被删了，则整个 NOT 也删掉（等价于去掉该约束）
				return false
			}
			return true

		case 3, 4, 5, 6, 7, 8: // =, substrings, >=, <=, present, ~=
			if attr, ok := attrFromNode(p); ok {
				if _, hit := drop[strings.ToLower(attr)]; hit {
					return false // 命中黑名单，删除该条件
				}
			}
			return true

		case 9: // extensibleMatch（可选处理：此处保留不动）
			return true
		}
	}
	// 其它未知情况，默认保留
	return true
}

// 从过滤节点里读出属性名（若能解析）
func attrFromNode(p *ber.Packet) (string, bool) {
	if p == nil {
		return "", false
	}
	// 等值/子串/比较 ~=/>=/<=：第一个子节点通常是属性名（OctetString）
	switch int(p.Tag) {
	case 3, 4, 5, 6, 8: // equality, substrings, ge, le, approx
		if len(p.Children) > 0 {
			if s, ok := p.Children[0].Value.(string); ok {
				return s, true
			}
		}
	case 7: // present: attr=*
		// 不同版本的 asn1-ber/ldap 编码略有差异，优先从 Value 拿不到就从第一个子节点尝试
		if s, ok := p.Value.(string); ok && s != "" {
			return s, true
		}
		if len(p.Children) > 0 {
			if s, ok := p.Children[0].Value.(string); ok {
				return s, true
			}
		}
	}
	return "", false
}
