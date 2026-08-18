package core

import (
	"github.com/lzpls/enimul/internal/addrtrie"
	"github.com/lzpls/enimul/internal/dial"
	"github.com/lzpls/enimul/internal/orderedmap"
	_ "github.com/lzpls/enimul/internal/platform"
)

const Version = "v0.4.0-alpha.6"

type Core struct {
	dns           dnsFields
	ttl           ttlProbingFields
	ipPools       *orderedmap.Map[*IPPool]
	defaultPolicy Policy
	hostsMatcher  *addrtrie.DomainMatcher[*dial.Dst]
	domainMatcher *addrtrie.DomainMatcher[*Policy]
	ipv4Matcher   *addrtrie.IPv4Trie[*Policy]
	ipv6Matcher   *addrtrie.IPv6Trie[*Policy]
}
