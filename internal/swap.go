package internal

import (
	"log"
	"strings"
)

type SwapAttributeNameRule struct {
	Rule map[string]string
}

// NewSwapAttributeNameRule ,对调name name1<->name2;name5<->name6
func NewSwapAttributeNameRule(rules ...string) *SwapAttributeNameRule {
	sanr := make(map[string]string)
	for _, r := range rules {
		swapRule := strings.Split(r, "<->")
		if len(swapRule) != 2 {
			log.Printf("invalid swap rule: %s\n", r)
			continue
		}
		log.Printf("swap %s to %s\n", swapRule[0], swapRule[1])
		log.Printf("swap %s to %s\n", swapRule[1], swapRule[0])
		sanr[swapRule[0]] = swapRule[1]
		sanr[swapRule[1]] = swapRule[0]
	}
	return &SwapAttributeNameRule{
		Rule: sanr,
	}
}
func (r *SwapAttributeNameRule) AfterSwapName(src string) string {
	val, ok := r.Rule[src]
	if ok {
		return val
	} else {
		return ""
	}
}
