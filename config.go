package main

import (
	"bufio"
	"bytes"
	"fmt"
	logger "github.com/feng-zh/go-any-proxy/internal/flogger"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"regexp"
	"strings"
	"unicode"
)

type ProxyRule struct {
	Proxy string    `yaml:"proxy"`
	Type  ProxyType `yaml:"type"`
	Rules []string  `yaml:"rules"`
}

type proxyConfig struct {
	proxyRules []ProxyRule
}

func NewProxyConfig(r io.Reader) *proxyConfig {
	config := new(proxyConfig)
	var err error
	if config.proxyRules, err = unmarshalProxyRules(r); err != nil {
		panic(fmt.Sprintf("error loading config: %v", err))
	}
	return config
}

func unmarshalProxyRules(r io.Reader) ([]ProxyRule, error) {
	scanner := bufio.NewScanner(r)
	sep := []byte("---\n")
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		sepIdx := bytes.Index(data, sep)
		if sepIdx >= 0 {
			if len(bytes.TrimSpace(data[:sepIdx])) == 0 {
				return sepIdx + len(sep), nil, nil
			} else {
				return sepIdx + len(sep), data[:sepIdx], nil
			}
		}
		return len(data), data, nil
	})
	list := make([]ProxyRule, 0)
	for scanner.Scan() {
		proxyRule := ProxyRule{}

		err := yaml.Unmarshal([]byte(scanner.Text()), &proxyRule)
		if err != nil {
			return nil, err
		}

		// default is http proxy if proxy has value
		if proxyRule.Type == "" && proxyRule.Proxy != "" {
			proxyRule.Type = HttpProxyType
		}

		list = append(list, proxyRule)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

func (config *proxyConfig) DirectorFunc(onlyNoProxy bool) []directorFunc {
	directorFuncs := make([]directorFunc, 0, 10)
	for _, cpr := range config.proxyRules {
		if cpr.Proxy == "" {
			for _, rule := range cpr.Rules {
				directorFuncs = append(directorFuncs, ruleAsDirectorFunc(rule))
			}
		}
	}
	if onlyNoProxy {
		return directorFuncs
	}
	proxyDirector := func(ptestip *net.IP) bool {
		if len(config.ResolveProxy(ptestip.String(), 0, []*Proxy{})) > 0 {
			return false
		} else {
			for _, f := range directorFuncs {
				if f(ptestip) {
					return true
				}
			}
			return false
		}
	}
	return []directorFunc{proxyDirector}
}

var findHostName = GetHostName

func ruleAsDirectorFunc(rule string) directorFunc {
	var dfunc directorFunc
	if isDomain(rule) {
		pattern := strings.Replace(rule, ".", "\\.", -1)
		pattern = strings.Replace(pattern, "*", ".*", -1)
		re, err := regexp.Compile(pattern)
		if err != nil {
			panic(fmt.Sprintf("Unnable to parse pattern %v", rule))
		}
		dfunc = func(ptestip *net.IP) bool {
			testIp := ptestip.String()
			hostname := findHostName(testIp)
			if hostname == "" {
				return false
			}
			hostname = strings.TrimSuffix(hostname, ".")
			return re.MatchString(hostname)
		}
	} else if isCIDR(rule) {
		_, directorIpNet, err := net.ParseCIDR(rule)
		if err != nil {
			panic(fmt.Sprintf("Unable to parse CIDR string : %s : %s\n", rule, err))
		}
		dfunc = func(ptestip *net.IP) bool {
			testIp := *ptestip
			return directorIpNet.Contains(testIp)
		}
	} else {
		// IP
		directorIp := net.ParseIP(rule)
		dfunc = func(ptestip *net.IP) bool {
			var testIp net.IP
			testIp = *ptestip
			return testIp.Equal(directorIp)
		}
	}
	return dfunc
}

func (config *proxyConfig) ResolveProxy(ipv4 string, port uint16, defaultProxyList []*Proxy) []*Proxy {
	var hostname *string = nil
	for _, cpr := range config.proxyRules {
		if cpr.Proxy != "" {
			proxy, err := ParseProxy(cpr.Proxy)
			if err != nil {
				panic(err)
			}
			proxy.Type = cpr.Type
			for _, rule := range cpr.Rules {
				if isDomain(rule) {
					pattern := strings.Replace(rule, ".", "\\.", -1)
					pattern = strings.Replace(pattern, "*", ".*", -1)
					re, err := regexp.Compile(pattern)
					if err != nil {
						panic(fmt.Sprintf("Unnable to parse pattern %v", rule))
					}
					if hostname == nil {
						h := findHostName(ipv4)
						hostname = &h
					}
					if *hostname == "" {
						continue
					}
					*hostname = strings.TrimSuffix(*hostname, ".")
					if re.MatchString(*hostname) {
						logger.Debugf("resolve proxy by domain %v(%v:%v): %v", *hostname, ipv4, port, cpr.Proxy)
						return insert(proxy, defaultProxyList)
					}
				} else if isCIDR(rule) {
					_, directorIpNet, err := net.ParseCIDR(rule)
					if err != nil {
						panic(fmt.Sprintf("Unable to parse CIDR string : %s : %s\n", rule, err))
					}
					if directorIpNet.Contains(net.ParseIP(ipv4)) {
						logger.Debugf("resolve proxy by IP net %v(%v:%v): %v", directorIpNet, ipv4, port, cpr.Proxy)
						return insert(proxy, defaultProxyList)
					}
				} else {
					// IP
					if rule == ipv4 {
						logger.Debugf("resolve proxy by IP %v:%v: %v", ipv4, port, cpr.Proxy)
						return insert(proxy, defaultProxyList)
					}
				}
			}
		}
	}
	return defaultProxyList
}

func insert(proxy *Proxy, list []*Proxy) []*Proxy {
	newList := make([]*Proxy, 1+len(list))
	newList[0] = proxy
	copy(newList[1:], list)
	return newList
}

func isDomain(rule string) bool {
	return strings.IndexFunc(rule, func(r rune) bool {
		return unicode.IsLetter(r)
	}) != -1
}

func isCIDR(rule string) bool {
	return strings.Contains(rule, "/")
}
