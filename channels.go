package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Optional channels (docs/luci-approvals.md, 8.7-8.9): features that widen who or what can act on
// the router, each off after install. Every switch is audited, and every channel carries the
// notice the Settings tab shows next to it: why it is off and how it can harm you.

type channel struct {
	Name   string `json:"name"`
	Title  string `json:"title"`
	Harm   string `json:"harm"`
	option string
	on     func(*Config) bool
}

var channels = []channel{
	{Name: "pair", Title: "Pair from LuCI", option: "pairing", on: func(c *Config) bool { return c.Pairing },
		Harm: "Anyone who can log in to LuCI with write access can add a key that reaches the router over SSH. " +
			"The key is limited to the MCP bridge, but its grants are whatever you give it."},
}

type channelRow struct {
	channel
	Enabled bool `json:"enabled"`
}

func channelReport(cfg *Config) []channelRow {
	rows := make([]channelRow, len(channels))
	for i, c := range channels {
		rows[i] = channelRow{c, c.on(cfg)}
	}
	return rows
}

func rpcdSetChannel(env rpcdEnv, raw json.RawMessage) (any, error) {
	var in struct {
		Channel string `json:"channel"`
		Enabled *bool  `json:"enabled"`
	}
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	i := slices.IndexFunc(channels, func(c channel) bool { return c.Name == in.Channel })
	if i < 0 || in.Enabled == nil {
		return nil, rpcdFail("give a channel (%s) and enabled", channelNames())
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}
	v := "0"
	if *in.Enabled {
		v = "1"
	}
	if err := setServerOption(env.configPath, channels[i].option, v); err != nil {
		return nil, rpcdFail("cannot write the setting: %v", err)
	}
	rpcdAudit(cfg, env, "set_channel", "", in.Channel, fmt.Sprintf("%s=%s", channels[i].option, v))
	return rpcdSettings(env, nil)
}

func channelNames() string {
	var n []string
	for _, c := range channels {
		n = append(n, c.Name)
	}
	return strings.Join(n, ", ")
}

// ---------------------------------------------------------------- pair from LuCI (8.7)

const defaultAuthorizedKeys = "/etc/dropbear/authorized_keys"

// rpcdPair writes the same forced-command line as `openwrt-mcp authorize-key`, then, unless the
// owner picked "none", the starting preset. A key with no grant can connect and do nothing.
func rpcdPair(env rpcdEnv, raw json.RawMessage) (any, error) {
	var in struct {
		Client   string `json:"client"`
		Pubkey   string `json:"pubkey"`
		Preset   string `json:"preset"`
		Duration string `json:"duration"`
	}
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}
	if !cfg.Pairing {
		return nil, rpcdFail("pairing from LuCI is off: switch it on under Settings first")
	}
	if !reClientName.MatchString(in.Client) {
		return nil, rpcdFail("bad client name %q", in.Client)
	}
	if in.Preset == "" {
		in.Preset = "readonly"
	}
	var blocks []presetPolicy
	if in.Preset != "none" {
		if blocks, err = expandPreset("@" + in.Preset); err != nil {
			return nil, rpcdFail("%v (or none)", err)
		}
		if in.Duration == "" {
			in.Duration = "7d"
		}
		if in.Duration != "never" && !slices.Contains(rpcdDurations, in.Duration) {
			return nil, rpcdFail("duration %q is not offered (%s, never)", in.Duration, strings.Join(rpcdDurations, ", "))
		}
	}
	path := env.authKeysPath
	if path == "" {
		path = defaultAuthorizedKeys
	}
	if _, err := authorizeKey(path, in.Client, in.Pubkey); err != nil {
		return nil, rpcdFail("%v", err)
	}
	if err := writeGrants(env.configPath, in.Client, blocks, in.Duration); err != nil {
		return nil, rpcdFail("the key is added but the grant is not written: %v", err)
	}
	sum := sha256.Sum256([]byte(strings.Fields(in.Pubkey)[1]))
	rpcdAudit(cfg, env, "pair", in.Client, "", fmt.Sprintf("key %s added, preset %s", hex.EncodeToString(sum[:6]), in.Preset))
	return map[string]any{"client": in.Client, "preset": in.Preset}, nil
}
