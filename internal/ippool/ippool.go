package ippool

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

var ippoolLog = ctrl.Log.WithName("ippool")

type Unit = struct{}

var Default = NewIPPool()

type IPPool struct {
	mu sync.RWMutex

	// store is a map from IPs to a slice of Kuberntes UIDs.
	// This maps an IP to the list of services defining it.
	store map[netip.Addr][]types.UID
	cs    []chan map[netip.Addr]Unit
}

func NewIPPool() *IPPool {
	return &IPPool{
		store: map[netip.Addr][]types.UID{},
		cs:    []chan map[netip.Addr]Unit{},
	}
}

func (p *IPPool) Subscribe() chan map[netip.Addr]Unit {
	p.mu.Lock()
	defer p.mu.Unlock()

	c := make(chan map[netip.Addr]Unit, 1)
	p.cs = append(p.cs, c)
	c <- p.copy()
	return c
}

func (p *IPPool) copy() (ips map[netip.Addr]Unit) {
	ips = make(map[netip.Addr]Unit, 0)
	for ip, _ := range p.store {
		ips[ip] = Unit{}
	}
	return
}

func extractExternalIPs(svc *corev1.Service) (ips []netip.Addr, err error) {
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		ippoolLog.Info("ignoring service as spec.type is not LoadBalancer", "namespace", svc.Namespace, "name", svc.Name)
		return
	}

	var ip netip.Addr
	for _, raw := range svc.Spec.ExternalIPs {
		ip, err = netip.ParseAddr(raw)
		if err != nil {
			err = fmt.Errorf("could not parse IP '%s' address in externalIPs: %w", raw, err)
			return
		}

		ips = append(ips, ip)
	}

	return
}

func (p *IPPool) HandleAdd(svc *corev1.Service) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ips, err := extractExternalIPs(svc)
	if err != nil {
		return err
	}

	updated := false
	for _, ip := range ips {
		if _, ok := p.store[ip]; !ok {
			p.store[ip] = []types.UID{}
			updated = true
		}

		p.store[ip] = append(p.store[ip], svc.UID)
	}

	if updated {
		p.notify()
	}

	return nil
}

func (p *IPPool) HandleDel(svc *corev1.Service) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ips, err := extractExternalIPs(svc)
	if err != nil {
		return err
	}

	updated := false
	for _, ip := range ips {
		if _, ok := p.store[ip]; !ok {
			ippoolLog.Error(
				fmt.Errorf("removed IP '%s' not resgistered in current state", ip),
				"error while handling service removal",
				"namespace", svc.Namespace, "name", svc.Name,
			)
			continue
		}

		p.store[ip] = slices.DeleteFunc(p.store[ip], func(id types.UID) bool { return id == svc.UID })
		if len(p.store[ip]) <= 0 {
			delete(p.store, ip)
			updated = true
		}
	}

	if updated {
		p.notify()
	}

	return nil
}

func (p *IPPool) notify() {
	export := p.copy()
	ippoolLog.Info("state updated", "state", maps.Keys(export))

	for _, c := range p.cs {
		c <- maps.Clone(export)
	}
}
