// Command nsdpctl is a minimal CLI around the internal/nsdp client for
// NETGEAR Plus switches.
//
// Usage:
//
//	nsdpctl [flags] name              read the switch system name (no password needed)
//	nsdpctl [flags] login             run the NSDP LOGIN handshake
//	nsdpctl [flags] set-name <value>  log in, set the system name, read it back
//	nsdpctl [flags] dump              typed config dump (GETs only, no login)
//	nsdpctl [flags] get <taghex>...   raw multi-tag GET (small tags batched; 0xNN00 as block reads)
//	nsdpctl [flags] block <idhex> [selhexbytes]
//	                                 raw block GET with optional selector bytes
//	nsdpctl [flags] set-raw <taghex> <valuehex>
//	                                 write ONE raw TLV (auth + user TLV), then read back
//
// Flags (must precede the subcommand):
//
//	-agent-mac string  target switch MAC, e.g. 8c:3b:ad:25:1b:88 (required for login and set-name)
//	-dest string       unicast NSDP destination host[:port] (default: broadcast 255.255.255.255:63322)
//	-iface string      network interface to use (default: first non-loopback interface with a hardware address, lowest index)
//	-password string   switch admin password (required for login and set-name)
//	-verbose           print the NSDP exchange (capability/nonce/token, retries, dropped packets, request bytes)
//
// `login` always prints the handshake summary (capability word, nonce,
// derived token) like the tools/nsdp-probe instrument. `set-name` logs in,
// prints the current name, applies the new value and reads it back; it
// exits 0 only on a matching read-back.
//
// Exit codes: 0 success (set-name: read-back matched), 1 failure (no
// reply, login rejected, set-name failed or mismatched), 2 usage error.
//
// WARNING: 3 failed login attempts lock ALL SET operations on the switch
// for ~30 minutes. Double-check the password before running login or
// set-name.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/lucavb/terraform-provider-netgear-plus/internal/nsdp"
)

func main() {
	ifaceFlag := flag.String("iface", "", "network interface to use (default: first non-loopback interface with a hardware address, lowest index)")
	agentFlag := flag.String("agent-mac", "", "target switch MAC, e.g. 8c:3b:ad:25:1b:88 (required for login and set-name)")
	passwordFlag := flag.String("password", "", "switch admin password (required for login and set-name)")
	verboseFlag := flag.Bool("verbose", false, "print the NSDP exchange: capability/nonce/token, retries, dropped packets, request bytes")
	flag.StringVar(&destFlag, "dest", "", "unicast NSDP destination host[:port] (default: broadcast 255.255.255.255:63322)")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	var err error
	switch args[0] {
	case "name":
		if len(args) != 1 {
			usage()
			os.Exit(2)
		}
		err = cmdName(*ifaceFlag, *agentFlag, *verboseFlag)
	case "login":
		if len(args) != 1 {
			usage()
			os.Exit(2)
		}
		err = cmdLogin(*ifaceFlag, *agentFlag, *passwordFlag)
	case "set-name":
		if len(args) != 2 {
			usage()
			os.Exit(2)
		}
		err = cmdSetName(*ifaceFlag, *agentFlag, *passwordFlag, args[1], *verboseFlag)
	case "dump":
		if len(args) != 1 {
			usage()
			os.Exit(2)
		}
		err = cmdDump(*ifaceFlag, *agentFlag, *verboseFlag)
	case "get":
		if len(args) < 2 {
			usage()
			os.Exit(2)
		}
		err = cmdGet(*ifaceFlag, *agentFlag, *verboseFlag, args[1:])
	case "block":
		if len(args) < 2 {
			usage()
			os.Exit(2)
		}
		err = cmdBlock(*ifaceFlag, *agentFlag, *verboseFlag, args[1:])
	case "set-raw":
		if len(args) != 3 {
			usage()
			os.Exit(2)
		}
		err = cmdSetRaw(*ifaceFlag, *agentFlag, *passwordFlag, args[1], args[2], *verboseFlag)
	case "reboot":
		if len(args) != 1 {
			usage()
			os.Exit(2)
		}
		err = cmdReboot(*ifaceFlag, *agentFlag, *passwordFlag, *verboseFlag)
	case "stats-reset":
		if len(args) != 1 {
			usage()
			os.Exit(2)
		}
		err = cmdStatsReset(*ifaceFlag, *agentFlag, *passwordFlag, *verboseFlag)
	case "pvid":
		if len(args) != 3 {
			usage()
			os.Exit(2)
		}
		err = cmdPVID(*ifaceFlag, *agentFlag, *passwordFlag, args[1], args[2], *verboseFlag)
	case "qos":
		if len(args) != 3 {
			usage()
			os.Exit(2)
		}
		err = cmdQoS(*ifaceFlag, *agentFlag, *passwordFlag, args[1], args[2], *verboseFlag)
	case "qos-mode":
		if len(args) != 2 {
			usage()
			os.Exit(2)
		}
		err = cmdQoSMode(*ifaceFlag, *agentFlag, *passwordFlag, args[1], *verboseFlag)
	case "multicast":
		if len(args) != 2 {
			usage()
			os.Exit(2)
		}
		err = cmdMulticast(*ifaceFlag, *agentFlag, *passwordFlag, args[1], *verboseFlag)
	case "bandwidth":
		if len(args) != 4 {
			usage()
			os.Exit(2)
		}
		err = cmdBandwidth(*ifaceFlag, *agentFlag, *passwordFlag, args[1], args[2], args[3], *verboseFlag)
	case "vlan":
		if len(args) < 3 || len(args) > 5 {
			usage()
			os.Exit(2)
		}
		err = cmdVLAN(*ifaceFlag, *agentFlag, *passwordFlag, args[1], args[2:], *verboseFlag)
	case "mirror":
		if len(args) < 2 {
			usage()
			os.Exit(2)
		}
		err = cmdMirror(*ifaceFlag, *agentFlag, *passwordFlag, args[1:], *verboseFlag)
	case "igmp":
		if len(args) < 1 || len(args) > 3 {
			usage()
			os.Exit(2)
		}
		err = cmdIGMP(*ifaceFlag, *agentFlag, *passwordFlag, args[1:], *verboseFlag)
	case "storm":
		if len(args) != 3 {
			usage()
			os.Exit(2)
		}
		err = cmdStorm(*ifaceFlag, *agentFlag, *passwordFlag, args[1], args[2], *verboseFlag)
	case "status":
		if len(args) != 3 {
			usage()
			os.Exit(2)
		}
		err = cmdStatus(*ifaceFlag, *agentFlag, *passwordFlag, args[1], args[2], *verboseFlag)
	case "flowcontrol":
		if len(args) != 3 {
			usage()
			os.Exit(2)
		}
		err = cmdFlowControl(*ifaceFlag, *agentFlag, *passwordFlag, args[1], args[2], *verboseFlag)
	case "mgmt":
		if len(args) < 1 {
			usage()
			os.Exit(2)
		}
		err = cmdMGMT(*ifaceFlag, *agentFlag, *passwordFlag, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "nsdpctl: unknown subcommand %q\n", args[0])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "nsdpctl: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  nsdpctl [flags] name              read the switch system name (no password needed)
  nsdpctl [flags] login              run the NSDP LOGIN handshake
  nsdpctl [flags] set-name <value>   log in, set the system name, read it back
  nsdpctl [flags] dump                typed config dump (GETs only, no login)
  nsdpctl [flags] get <taghex>...     raw multi-tag GET (small tags batched; 0xNN00 as block reads)
  nsdpctl [flags] block <idhex> [selhexbytes]
                                       raw block GET with optional selector bytes
  nsdpctl [flags] set-raw <taghex> <valuehex>
                                       write ONE raw TLV (auth + user TLV), then read back

  nsdpctl [flags] reboot             destructive: reboot the switch
  nsdpctl [flags] stats-reset         reset per-port traffic statistics
  nsdpctl [flags] pvid <port> <vlan>  set port-based VLAN ID for a port (port 1-8)
  nsdpctl [flags] qos <port> <prio>   set QoS priority (port 1-8; prio: high|middle|normal|low)
  nsdpctl [flags] qos-mode <port-based|802.1p>
                                        set the global QoS scheduling mode
  nsdpctl [flags] multicast <on|off>
                                        block or allow unknown multicast (global toggle)
  nsdpctl [flags] bandwidth <dir> <port> <limit>
                                       set ingress/egress/storm rate limit on a port
  nsdpctl [flags] vlan <type> <id> [ports]
                                       set port-based vlan or 802.1q vlan (port-based|802.1q|del-802.1q)
  nsdpctl [flags] mirror <dest> [src1,src2,...]
                                       configure port mirroring (dest=0 to disable)
  nsdpctl [flags] igmp [on|off] [vlan]
                                       set IGMP snooping enabled state and VLAN
  nsdpctl [flags] storm <port> <limit>
                                       set broadcast storm rate limit (port 1-8)
  nsdpctl [flags] status <port> <up|down|enable|disable>
                                        set a port's ADMIN state (1-8), preserving its flow-control byte
  nsdpctl [flags] flowcontrol <port> <enable|disable>
                                        set a port's FLOW CONTROL (1-8), preserving its admin byte
  nsdpctl [flags] mgmt <ip> [netmask|dhcp|static] [gateway]
                                        set management IP / netmask / DHCP mode / gateway

flags (must precede the subcommand):
  -agent-mac string   target switch MAC, e.g. 8c:3b:ad:25:1b:88 (required for login, set-name;
                      required for all write operations)
  -dest string        unicast NSDP destination host[:port] (default: broadcast 255.255.255.255:63322)
  -iface string       network interface (default: first non-loopback with a hardware address, lowest index)
  -password string    switch admin password (required for login, set-name and all write operations)
  -verbose            print the NSDP exchange: capability/nonce/token, retries, request bytes

read-only subcommands (name/dump/get/block) never log in. All write operations require login:
they print a lockout warning and can misconfigure a real switch.
`)
}

// destFlag holds the -dest flag value: optional unicast NSDP destination
// host[:port], empty = the default limited-broadcast. A package-level var
// because every cmd* funnels through the shared newClient below.
var destFlag string

// newClient wires the flags into nsdp.NewClient.
func newClient(iface, agent, password string, verbose io.Writer) (*nsdp.Client, error) {
	return nsdp.NewClient(nsdp.Options{
		IfaceName: iface,
		AgentMAC:  agent,
		Password:  []byte(password),
		Dest:      destFlag,
		Verbose:   verbose,
	})
}

// warnLockout mirrors the probe instrument's warning before any flow that
// can burn a login attempt.
func warnLockout() {
	fmt.Fprintln(os.Stderr, "NOTE: 3 failed login attempts lock ALL SET operations on the switch for ~30 minutes.")
}

// cmdName reads the switch system name via an unauthenticated GET.
func cmdName(iface, agent string, verbose bool) error {
	var v io.Writer
	if verbose {
		v = os.Stderr
	}
	c, err := newClient(iface, agent, "", v)
	if err != nil {
		return err
	}
	defer c.Close()
	name, err := c.GetSystemName()
	if err != nil {
		return fmt.Errorf("read system name: %w", err)
	}
	fmt.Printf("name: %q\n", name)
	return nil
}

// cmdLogin runs the NSDP LOGIN handshake and prints the exchange summary
// (capability word, nonce, derived token) like the probe instrument.
func cmdLogin(iface, agent, password string) error {
	if agent == "" {
		return errors.New("login requires -agent-mac: the login token is derived from the switch MAC")
	}
	if password == "" {
		return errors.New("login requires -password")
	}
	warnLockout()
	// The exchange summary IS the output of this subcommand.
	c, err := newClient(iface, agent, password, os.Stdout)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	fmt.Println("login OK")
	return nil
}

// cmdSetName logs in, prints the current system name, applies the new
// value and reads it back. It returns nil (exit 0) only on a matching
// read-back.
func cmdSetName(iface, agent, password, value string, verbose bool) error {
	if agent == "" {
		return errors.New("set-name requires -agent-mac: the login token is derived from the switch MAC")
	}
	if password == "" {
		return errors.New("set-name requires -password: the system-name SET must follow the NSDP LOGIN handshake")
	}
	warnLockout()
	var v io.Writer
	if verbose {
		v = os.Stdout
	}
	c, err := newClient(iface, agent, password, v)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	old, err := c.GetSystemName()
	if err != nil {
		return fmt.Errorf("read current system name: %w", err)
	}
	fmt.Printf("current name: %q\n", old)
	if err := c.SetSystemName(value); err != nil {
		return fmt.Errorf("set system name: %w", err)
	}
	got, err := c.GetSystemName()
	if err != nil {
		return fmt.Errorf("read back system name: %w", err)
	}
	fmt.Printf("read-back name: %q\n", got)
	if got == value {
		fmt.Printf("read-back match: system name is now %q\n", value)
		return nil
	}
	return fmt.Errorf("read-back MISMATCH: got %q, want %q", got, value)
}

// --- Write command implementations ----------------------------------------

func cmdReboot(iface, agent, password string, verbose bool) error {
	if agent == "" {
		return errors.New("reboot requires -agent-mac")
	}
	if password == "" {
		return errors.New("reboot requires -password")
	}
	warnLockout()
	fmt.Fprintln(os.Stderr, "WARNING: this will reboot the switch. All sessions will be dropped.")
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := c.SetReboot(); err != nil {
		return fmt.Errorf("reboot: %w", err)
	}
	fmt.Println("reboot command sent — switch is restarting")
	return nil
}

func cmdStatsReset(iface, agent, password string, verbose bool) error {
	if agent == "" {
		return errors.New("stats-reset requires -agent-mac")
	}
	if password == "" {
		return errors.New("stats-reset requires -password")
	}
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := c.ResetPortStats(); err != nil {
		return fmt.Errorf("reset port stats: %w", err)
	}
	fmt.Println("port stats reset command sent")
	return nil
}

func cmdPVID(iface, agent, password, portStr, vlanStr string, verbose bool) error {
	if agent == "" {
		return errors.New("pvid requires -agent-mac")
	}
	if password == "" {
		return errors.New("pvid requires -password")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("port %q: %w", portStr, err)
	}
	vlanID, err := strconv.Atoi(vlanStr)
	if err != nil {
		return fmt.Errorf("vlan id %q: %w", vlanStr, err)
	}
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := c.SetPVID(port, vlanID); err != nil {
		return fmt.Errorf("set pvid: %w", err)
	}
	fmt.Printf("PVID set: port %d → VLAN %d\n", port, vlanID)
	return nil
}

func cmdQoS(iface, agent, password, portStr, prioStr string, verbose bool) error {
	if agent == "" {
		return errors.New("qos requires -agent-mac")
	}
	if password == "" {
		return errors.New("qos requires -password")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("port %q: %w", portStr, err)
	}
	prio := map[string]nsdp.QoSPriority{
		"high":   1,
		"middle": 2,
		"normal": 3,
		"low":    4,
	}
	p, ok := prio[strings.ToLower(prioStr)]
	if !ok {
		return fmt.Errorf("priority %q: want high|middle|normal|low", prioStr)
	}
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := c.SetQoSPriority(port, p); err != nil {
		return fmt.Errorf("set qos: %w", err)
	}
	fmt.Printf("QoS set: port %d → %s\n", port, p.String())
	return nil
}

func cmdBandwidth(iface, agent, password, dir, portStr, limitStr string, verbose bool) error {
	if agent == "" {
		return errors.New("bandwidth requires -agent-mac")
	}
	if password == "" {
		return errors.New("bandwidth requires -password")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("port %q: %w", portStr, err)
	}
	limit := mapBandwidthLimit(dir, limitStr)
	tag := nsdp.TagIngressRate
	switch strings.ToLower(dir) {
	case "egress", "out", "outgoing":
		tag = nsdp.TagEgressRate
	case "storm", "broadcast":
		tag = nsdp.TagBroadcastStormRate
	default:
		tag = nsdp.TagIngressRate // default: ingress
	}
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	switch tag {
	case nsdp.TagIngressRate:
		if err := c.SetIngressRate(port, limit); err != nil {
			return fmt.Errorf("set ingress rate: %w", err)
		}
	case nsdp.TagEgressRate:
		if err := c.SetEgressRate(port, limit); err != nil {
			return fmt.Errorf("set egress rate: %w", err)
		}
	case nsdp.TagBroadcastStormRate:
		if err := c.SetBroadcastStormRate(port, limit); err != nil {
			return fmt.Errorf("set storm rate: %w", err)
		}
	}
	fmt.Printf("bandwidth set: %s port %d → %s\n", dir, port, limit.String())
	return nil
}

// mapBandwidthLimit converts a string to nsdp.BandwidthLimit.
func mapBandwidthLimit(dir, limitStr string) nsdp.BandwidthLimit {
	l := strings.ToUpper(limitStr)
	switch l {
	case "NONE", "0":
		return nsdp.BandwidthNone
	case "512K", "0.5M", "1":
		return nsdp.Bandwidth512K
	case "1M", "2":
		return nsdp.Bandwidth1M
	case "2M", "3":
		return nsdp.Bandwidth2M
	case "4M", "4":
		return nsdp.Bandwidth4M
	case "8M", "5":
		return nsdp.Bandwidth8M
	case "16M", "6":
		return nsdp.Bandwidth16M
	case "32M", "7":
		return nsdp.Bandwidth32M
	case "64M", "8":
		return nsdp.Bandwidth64M
	case "128M", "9":
		return nsdp.Bandwidth128M
	case "256M", "10":
		return nsdp.Bandwidth256M
	case "512M", "11":
		return nsdp.Bandwidth512M
	default:
		// Try parsing as numeric enum
		if n, err := strconv.Atoi(l); err == nil {
			return nsdp.BandwidthLimit(n)
		}
		return nsdp.BandwidthNone
	}
}

func cmdVLAN(iface, agent, password, vtype string, args []string, verbose bool) error {
	if agent == "" {
		return errors.New("vlan requires -agent-mac")
	}
	if password == "" {
		return errors.New("vlan requires -password")
	}
	vlanID, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("vlan id %q: %w", args[0], err)
	}

	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	switch strings.ToLower(vtype) {
	case "port-based":
		if len(args) < 2 {
			return errors.New("vlan port-based: need vlan_id and ports (comma-separated, e.g. 1,2,3)")
		}
		ports, err := parsePortList(args[1])
		if err != nil {
			return err
		}
		if err := c.SetPortBasedVLAN(vlanID, ports); err != nil {
			return fmt.Errorf("set port-based vlan: %w", err)
		}
		fmt.Printf("port-based VLAN %d: ports %v\n", vlanID, ports)
	case "802.1q", "qinQ":
		if len(args) < 3 {
			return errors.New("vlan 802.1q: need vlan_id, tagged_ports, untagged_ports (e.g. 10 1,2,3 4,5)")
		}
		tagged, err := parsePortList(args[1])
		if err != nil {
			return err
		}
		untagged, err := parsePortList(args[2])
		if err != nil {
			return err
		}
		if err := c.Set8021QVLAN(vlanID, tagged, untagged); err != nil {
			return fmt.Errorf("set 802.1q vlan: %w", err)
		}
		fmt.Printf("802.1Q VLAN %d: tagged=%v untagged=%v\n", vlanID, tagged, untagged)
	case "del-802.1q":
		if err := c.Delete8021QVLAN(vlanID); err != nil {
			return fmt.Errorf("delete 802.1q vlan: %w", err)
		}
		fmt.Printf("deleted 802.1Q VLAN %d\n", vlanID)
	default:
		return fmt.Errorf("vlan type %q: want port-based|802.1q|del-802.1q", vtype)
	}
	return nil
}

func cmdMirror(iface, agent, password string, args []string, verbose bool) error {
	if agent == "" {
		return errors.New("mirror requires -agent-mac")
	}
	if password == "" {
		return errors.New("mirror requires -password")
	}
	if len(args) < 1 {
		return errors.New("mirror: need destination port")
	}
	dest, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("dest port %q: %w", args[0], err)
	}
	var srcPorts []int
	if len(args) > 1 {
		srcPorts, err = parsePortList(args[1])
		if err != nil {
			return err
		}
	}
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := c.SetPortMirroring(dest, srcPorts); err != nil {
		return fmt.Errorf("set port mirror: %w", err)
	}
	if dest == 0 {
		fmt.Println("port mirroring disabled")
	} else {
		fmt.Printf("port mirroring: src %v → dst %d\n", srcPorts, dest)
	}
	return nil
}

func cmdIGMP(iface, agent, password string, args []string, verbose bool) error {
	if agent == "" {
		return errors.New("igmp requires -agent-mac")
	}
	if password == "" {
		return errors.New("igmp requires -password")
	}
	enabled := true
	vlanID := uint16(1)
	if len(args) > 0 {
		switch strings.ToLower(args[0]) {
		case "off", "0", "false", "disable":
			enabled = false
		case "on", "1", "true", "enable":
			enabled = true
		default:
			// Try parsing as VLAN ID, assume enabled
			if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
				enabled = true
				vlanID = uint16(n)
			} else {
				return fmt.Errorf("igmp: first arg must be on/off or a VLAN ID")
			}
		}
	}
	if len(args) > 1 {
		n, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("vlan id %q: %w", args[1], err)
		}
		vlanID = uint16(n)
	}
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := c.SetIGMPSnooping(enabled, vlanID); err != nil {
		return fmt.Errorf("set igmp snooping: %w", err)
	}
	fmt.Printf("IGMP snooping: %s vlan %d\n", boolStr(enabled), vlanID)
	return nil
}

func cmdStorm(iface, agent, password, portStr, limitStr string, verbose bool) error {
	if agent == "" {
		return errors.New("storm requires -agent-mac")
	}
	if password == "" {
		return errors.New("storm requires -password")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("port %q: %w", portStr, err)
	}
	limit := mapBandwidthLimit("storm", limitStr)
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := c.SetBroadcastStormRate(port, limit); err != nil {
		return fmt.Errorf("set storm rate: %w", err)
	}
	fmt.Printf("storm rate: port %d → %s\n", port, limit.String())
	return nil
}

// mapOnOffStrict parses an enable/disable verb argument. acceptUpDown
// additionally accepts up|down as synonyms for enable|disable (the status
// verb keeps its legacy wording).
func mapOnOffStrict(stateStr string, acceptUpDown bool) (bool, error) {
	switch strings.ToLower(stateStr) {
	case "enable", "on":
		return true, nil
	case "disable", "off":
		return false, nil
	case "up":
		if acceptUpDown {
			return true, nil
		}
	case "down":
		if acceptUpDown {
			return false, nil
		}
	}
	if acceptUpDown {
		return false, fmt.Errorf("state %q: want up|down|enable|disable", stateStr)
	}
	return false, fmt.Errorf("state %q: want enable|disable", stateStr)
}

// getPortAdminEntry reads the 0x9400 block and returns the entry for port.
// A GET failure or a missing port entry is a clear error: the
// read-modify-write verbs refuse to guess the preserved byte.
func getPortAdminEntry(c *nsdp.Client, port int) (nsdp.PortAdminStatusEntry, error) {
	attrs, err := c.GetBlock(0x94, nil)
	if err != nil {
		return nsdp.PortAdminStatusEntry{}, fmt.Errorf("read port config table (block 0x94): %w", err)
	}
	for _, a := range attrs {
		entries, ok := a.Decoded.([]nsdp.PortAdminStatusEntry)
		if !ok {
			continue
		}
		for _, e := range entries {
			if int(e.Port) == port {
				return e, nil
			}
		}
	}
	return nsdp.PortAdminStatusEntry{}, fmt.Errorf("port %d not found in the 0x9400 port config table", port)
}

// cmdStatus is the ADMIN verb: read-modify-write on the 0x9400 block —
// GET the table first, preserve the port's current flow-control byte,
// then SetPortConfig(port, admin, existingFlow). The firmware always
// writes all three bytes per port, so the preserved byte must come from
// the live table, never from a guess.
func cmdStatus(iface, agent, password, portStr, stateStr string, verbose bool) error {
	if agent == "" {
		return errors.New("status requires -agent-mac")
	}
	if password == "" {
		return errors.New("status requires -password")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("port %q: %w", portStr, err)
	}
	admin, err := mapOnOffStrict(stateStr, true)
	if err != nil {
		return err
	}
	warnLockout()
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	entry, err := getPortAdminEntry(c, port)
	if err != nil {
		return err
	}
	if err := c.SetPortConfig(port, admin, entry.Flow != 0); err != nil {
		return fmt.Errorf("set port admin state: %w", err)
	}
	fmt.Printf("port %d: admin %s (flow control preserved %s)\n", port, boolStr(admin), boolStr(entry.Flow != 0))
	return nil
}

// cmdFlowControl is the flow-control verb: read-modify-write on the
// 0x9400 block preserving the port's current admin byte.
func cmdFlowControl(iface, agent, password, portStr, stateStr string, verbose bool) error {
	if agent == "" {
		return errors.New("flowcontrol requires -agent-mac")
	}
	if password == "" {
		return errors.New("flowcontrol requires -password")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("port %q: %w", portStr, err)
	}
	flow, err := mapOnOffStrict(stateStr, false)
	if err != nil {
		return err
	}
	warnLockout()
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	entry, err := getPortAdminEntry(c, port)
	if err != nil {
		return err
	}
	if err := c.SetPortConfig(port, entry.Admin != 0, flow); err != nil {
		return fmt.Errorf("set port flow control: %w", err)
	}
	fmt.Printf("port %d: flow control %s (admin preserved %s)\n", port, boolStr(flow), boolStr(entry.Admin != 0))
	return nil
}

// cmdQoSMode sets the global QoS scheduling mode (port-based or 802.1p).
func cmdQoSMode(iface, agent, password, modeStr string, verbose bool) error {
	if agent == "" {
		return errors.New("qos-mode requires -agent-mac")
	}
	if password == "" {
		return errors.New("qos-mode requires -password")
	}
	var mode nsdp.QoSMode
	switch strings.ToLower(modeStr) {
	case "port-based", "port", "1":
		mode = nsdp.QoSModePortBased
	case "802.1p", "dot1p", "2":
		mode = nsdp.QoSMode8021p
	default:
		return fmt.Errorf("qos mode %q: want port-based|802.1p", modeStr)
	}
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := c.SetQoSMode(mode); err != nil {
		return fmt.Errorf("set qos mode: %w", err)
	}
	fmt.Printf("QoS mode: %s\n", mode)
	return nil
}

// cmdMulticast sets the block-unknown-multicast global toggle.
func cmdMulticast(iface, agent, password, stateStr string, verbose bool) error {
	if agent == "" {
		return errors.New("multicast requires -agent-mac")
	}
	if password == "" {
		return errors.New("multicast requires -password")
	}
	switch strings.ToLower(stateStr) {
	case "on", "block", "enable":
	case "off", "allow", "disable":
	default:
		return fmt.Errorf("multicast state %q: want on|off", stateStr)
	}
	blocked := strings.ToLower(stateStr) == "on" ||
		strings.ToLower(stateStr) == "block" ||
		strings.ToLower(stateStr) == "enable"
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := c.SetBlockUnknownMulticast(blocked); err != nil {
		return fmt.Errorf("set block unknown multicast: %w", err)
	}
	fmt.Printf("block unknown multicast: %s\n", boolStr(blocked))
	return nil
}

func cmdMGMT(iface, agent, password string, args []string) error {
	if agent == "" {
		return errors.New("mgmt requires -agent-mac")
	}
	if password == "" {
		return errors.New("mgmt requires -password")
	}
	c, err := newClient(iface, agent, password, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Login(); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	if len(args) < 1 {
		return errors.New("mgmt: need at least IP address (optionally followed by netmask or dhcp|static, then gateway)")
	}
	if err := c.SetIPAddress(args[0]); err != nil {
		return fmt.Errorf("set ip: %w", err)
	}
	fmt.Printf("IP address: %s\n", args[0])
	if len(args) >= 2 {
		switch strings.ToLower(args[1]) {
		case "dhcp":
			if err := c.SetDHCPMode(1); err != nil {
				return fmt.Errorf("set dhcp mode: %w", err)
			}
			fmt.Println("DHCP mode: dhcp")
		case "static":
			if err := c.SetDHCPMode(0); err != nil {
				return fmt.Errorf("set dhcp mode: %w", err)
			}
			fmt.Println("DHCP mode: static")
		default:
			if err := c.SetSubnetMask(args[1]); err != nil {
				return fmt.Errorf("set netmask: %w", err)
			}
			fmt.Printf("subnet mask: %s\n", args[1])
		}
	}
	if len(args) >= 3 {
		if err := c.SetGatewayAddr(args[2]); err != nil {
			return fmt.Errorf("set gateway: %w", err)
		}
		fmt.Printf("gateway: %s\n", args[2])
	}
	return nil
}

// parsePortList parses a comma-separated list of port numbers (1-8).
func parsePortList(s string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("port %q: %w", part, err)
		}
		if p < 1 || p > 8 {
			return nil, fmt.Errorf("port %d out of range [1,8]", p)
		}
		ports = append(ports, p)
	}
	if len(ports) == 0 {
		return nil, errors.New("empty port list")
	}
	return ports, nil
}

// boolStr returns "on" or "off".
func boolStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
