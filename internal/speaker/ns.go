package speaker

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/teapotovh/dummylb/internal/ippool"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	nsspkrLog    = ctrl.Log.WithName("nsspkr")
	nsdspkrLog   = ctrl.Log.WithName("nsdspkr")
	ip6tablesLog = ctrl.Log.WithName("ip6tables")
	multicastMAC = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
)

const IPTABLES_CHAIN_NAME = "dummylb"

type NSSpeaker struct {
	iface string
	trace bool

	handle  *afpacket.TPacket
	psource *gopacket.PacketSource
	packets chan pkt
	mac     net.HardwareAddr
	ll      *netip.Addr
	iptb    *iptables.IPTables
}

func NewNSSpeaker(iface string, trace bool) *NSSpeaker {
	return &NSSpeaker{
		iface: iface,
		trace: trace,
	}
}

func fetchLL(iface *net.Interface) (*netip.Addr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("error while reading NS interface IP addresses: %w", err)
	}

	// ll is the link-local IPv6
	var ll *netip.Addr = nil
	for _, addr := range addrs {
		ip, err := netip.ParsePrefix(addr.String())
		if err != nil {
			nsspkrLog.Error(err, "error while parsing IP associaeted with NS interface", "iface", iface, "addr", addr.String())
			continue
		}

		addr := ip.Addr()
		if addr.Is6() && addr.IsLinkLocalUnicast() {
			ll = &addr
			break
		}
	}

	return ll, nil
}

func (a *NSSpeaker) Start(ctx context.Context) error {
	iface, err := net.InterfaceByName(a.iface)
	if err != nil {
		return fmt.Errorf("error while getting NS interface: %w", err)
	}
	a.mac = iface.HardwareAddr

	a.ll, err = fetchLL(iface)
	if err != nil {
		return err
	}
	if a.ll == nil {
		return fmt.Errorf("could not find link-local IPv6 address on NS interface: %s", a.iface)
	}

	a.handle, err = afpacket.NewTPacket(afpacket.OptInterface(a.iface))
	if err != nil {
		return fmt.Errorf("error while sniffing for NS pakcets: %w", err)
	}
	a.psource = gopacket.NewPacketSource(a.handle, layers.LinkTypeEthernet)

	iptb, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return fmt.Errorf("error while initializing iptables: %w", err)
	}

	chain_exists, err := iptb.ChainExists("filter", IPTABLES_CHAIN_NAME)
	if err != nil {
		return fmt.Errorf("error while checking if iptables chain exists: %w", err)
	}
	if !chain_exists {
		if err := iptb.NewChain("filter", IPTABLES_CHAIN_NAME); err != nil {
			return fmt.Errorf("error while creating iptables chain: %w", err)
		}

		iptb.Insert("filter", "FORWARD", 1, "-i", a.iface, "-j", IPTABLES_CHAIN_NAME)
	}

	a.iptb = iptb

	go a.pcap(ctx)
	go a.speaker(ctx)
	go a.advertiser(ctx)
	go a.ip6tables(ctx)

	<-ctx.Done()
	return nil
}

func filterIPv6s(ips map[netip.Addr]ippool.Unit) map[netip.Addr]ippool.Unit {
	result := map[netip.Addr]ippool.Unit{}
	for ip, _ := range ips {
		if ip.Is6() {
			result[ip] = ippool.Unit{}
		}
	}
	return result
}

// TODO(lucat1): look into avoiding these conversions between netip.Addr and net.IP

func netToNetip(ip *net.IP) netip.Addr {
	a, _ := netip.ParseAddr(ip.String())
	return a
}

func netipToNet(ip *netip.Addr) net.IP {
	return net.ParseIP(ip.String())
}

func (a *NSSpeaker) speaker(ctx context.Context) {
	nsspkrLog.Info("starting NS speaker", "interface", a.iface)
	updates := ippool.Default.Subscribe()

	ips := map[netip.Addr]ippool.Unit{}
	buf := gopacket.NewSerializeBuffer()
	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
			break
		case update := <-updates:
			ips = filterIPv6s(update)
			nsspkrLog.Info("got ip configuration update", "update", ips)
			break
		case pkt := <-a.packets:
			eth := pkt.packet.LinkLayer().(*layers.Ethernet)
			ip := pkt.packet.NetworkLayer().(*layers.IPv6)
			ns := pkt.layer.(*layers.ICMPv6NeighborSolicitation)
			dstIP := netToNetip(&ns.TargetAddress)

			if _, registered := ips[dstIP]; registered {
				if a.trace {
					nsspkrLog.Info("got NS request",
						"dst.ip", dstIP, "dst.ll", a.ll,
						"src.ip", ip.SrcIP,
					)
				}
				eth := &layers.Ethernet{
					SrcMAC:       a.mac,
					DstMAC:       eth.SrcMAC,
					EthernetType: layers.EthernetTypeIPv6,
				}
				ipv6 := &layers.IPv6{
					Version:    6,
					SrcIP:      netipToNet(a.ll).To16(),
					DstIP:      ip.SrcIP.To16(),
					NextHeader: layers.IPProtocolICMPv6,
					HopLimit:   255,
				}
				icmp := &layers.ICMPv6{
					TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
				}
				icmp.SetNetworkLayerForChecksum(ipv6)
				na := &layers.ICMPv6NeighborAdvertisement{
					Flags:         0x60,
					TargetAddress: netipToNet(&dstIP),
					Options: []layers.ICMPv6Option{{
						Type: layers.ICMPv6OptTargetAddress,
						Data: a.mac,
					}},
				}

				if err := buf.Clear(); err != nil {
					nsspkrLog.Error(err, "error while clearing packet buffer")
					continue
				}
				err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
					ComputeChecksums: true,
					FixLengths:       true,
				}, eth, ipv6, icmp, na)
				if err != nil {
					nsspkrLog.Error(err, "error while serializing NA reply")
					continue
				}
				if err := a.handle.WritePacketData(buf.Bytes()); err != nil {
					nsspkrLog.Error(err, "error while writing NA reply on the wire")
					continue
				}

				if a.trace {
					nsspkrLog.Info("sent NA reply", "packet", na)
				}
			}
			break
		}
	}

	nsspkrLog.Info("stopped NS speaker")
	close(updates)
}

func (a *NSSpeaker) unsolicited(ips map[netip.Addr]ippool.Unit) {
	allLL := netip.IPv6LinkLocalAllNodes()
	buf := gopacket.NewSerializeBuffer()

	for dstIP, _ := range ips {
		eth := &layers.Ethernet{
			SrcMAC:       a.mac,
			DstMAC:       multicastMAC,
			EthernetType: layers.EthernetTypeIPv6,
		}
		ipv6 := &layers.IPv6{
			Version:    6,
			SrcIP:      netipToNet(a.ll).To16(),
			DstIP:      netipToNet(&allLL),
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   255,
		}
		icmp := &layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
		}
		icmp.SetNetworkLayerForChecksum(ipv6)
		na := &layers.ICMPv6NeighborAdvertisement{
			Flags:         0x20,
			TargetAddress: netipToNet(&dstIP),
			Options: []layers.ICMPv6Option{
				{
					Type: layers.ICMPv6OptTargetAddress,
					Data: a.mac,
				},
			},
		}

		if err := buf.Clear(); err != nil {
			nsdspkrLog.Error(err, "error while clearing packet buffer")
			continue
		}
		err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}, eth, ipv6, icmp, na)
		if err != nil {
			nsdspkrLog.Error(err, "error while serializing NA reply")
			continue
		}
		if err := a.handle.WritePacketData(buf.Bytes()); err != nil {
			nsdspkrLog.Error(err, "error while writing NA reply on the wire")
			continue
		}

		if a.trace {
			nsdspkrLog.Info("sent unsolicited NA", "packet", na)
		}
	}
}

func (a *NSSpeaker) advertiser(ctx context.Context) {
	nsdspkrLog.Info("starting NS unsolicited advertiser", "interface", a.iface)
	updates := ippool.Default.Subscribe()

	ips := map[netip.Addr]ippool.Unit{}
	running := true
	ticker := time.NewTicker(time.Minute / 2)
	for running {
		select {
		case <-ctx.Done():
			running = false
			break
		case update := <-updates:
			ips = filterIPv6s(update)
			nsdspkrLog.Info("got ip configuration update", "update", ips)
			a.unsolicited(ips)
			break
		case <-ticker.C:
			a.unsolicited(ips)
			break
		}
	}

	nsdspkrLog.Info("stopped NS unsolicited advertiser")
	close(updates)
}

func (a *NSSpeaker) pcap(ctx context.Context) {
	nsspkrLog.Info("starting NS sniffer")
	a.packets = make(chan pkt)

	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
			break
		default:
		}

		packet, err := a.psource.NextPacket()
		if err == afpacket.ErrTimeout {
			continue
		} else if err == io.EOF {
			running = false
			continue
		} else if err != nil {
			nsspkrLog.Error(err, "error while reading NS packet")
			time.Sleep(time.Second)
			continue
		}

		if nsLayer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation); nsLayer != nil {
			a.packets <- pkt{packet: packet, layer: nsLayer}
		}
	}

	close(a.packets)
	nsspkrLog.Info("stopped NS sniffer")
}

func (a *NSSpeaker) ip6tables(ctx context.Context) {
	ip6tablesLog.Info("starting ip6tables updater")
	updates := ippool.Default.Subscribe()
	running := true

	for running {
		select {
		case <-ctx.Done():
			running = false
			break
		case update := <-updates:
			ips := filterIPv6s(update)
			ip6tablesLog.Info("got ip configuration update", "update", ips)

			err := a.iptb.ClearChain("filter", IPTABLES_CHAIN_NAME)
			if err != nil {
				ip6tablesLog.Error(err, "error while clearing ip6tables rules")
				continue
			}

			for ip := range ips {
				if err := a.iptb.AppendUnique("filter", IPTABLES_CHAIN_NAME, "-s", ip.String(), "-p", "icmpv6", "--icmpv6-type", "echo-request", "-j", "ACCEPT"); err != nil {
					ip6tablesLog.Error(err, "error while updating ip6tables rules", "ip", ip.String())
				}
			}
			break
		}
	}

	ip6tablesLog.Info("stopped ip6tables updater")
	close(updates)
}
