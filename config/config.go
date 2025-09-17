package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ServAddr   string       `yaml:"servAddr"`
	ServUser   string       `yaml:"servUser"`
	ServPass   string       `yaml:"servPass"`
	Debug      bool         `yaml:"debug"`
	LdapConfig []LdapConfig `yaml:"ldapConfig"`
}

type LdapConfig struct {
	SuffixDN              string   `yaml:"suffixDN"`
	LdapURL               string   `yaml:"ldapURL"`
	BindDN                string   `yaml:"bindDN"`
	BindPW                string   `yaml:"bindPW"`
	InsecureSkipVerify    bool     `yaml:"insecureSkipVerify"`
	ClientPoolSize        int      `yaml:"clientPoolSize"`
	SwapAttributeNameRule []string `yaml:"swapAttributeNameRule"`
	ExtraAttributes       []string `yaml:"extraAttributes"`
}

func ParseConfig(f string) (*Config, error) {
	fb, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := yaml.Unmarshal(fb, &config); err != nil {
		return nil, err
	}
	return &config, nil
}
