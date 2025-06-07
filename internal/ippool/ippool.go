package ippool

import (
	"net"
	"sync"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

var ippoolLog = ctrl.Log.WithName("ippool")

type IPPool struct {
	mu  sync.RWMutex
	v4s []net.IP
	v6s []net.IP
}

func NewIPPool() *IPPool {
	return &IPPool{
		v4s: make([]net.IP, 0),
		v6s: make([]net.IP, 0),
	}
}

var Default = NewIPPool()

func (p *IPPool) HandleAdd(svc *corev1.Service) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return nil
}

func (p *IPPool) HandleDel(svc *corev1.Service) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return nil
}
