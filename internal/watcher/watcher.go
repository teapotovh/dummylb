package watcher

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
)

var watcherLog = ctrl.Log.WithName("watcher")

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services/status,verbs=get

type NotifyFunc func(*corev1.Service) error

// ServiceWatcher watches for service changes and notifies consumers through a callback
type ServiceWatcher struct {
	cache    ctrlcache.Cache
	informer ctrlcache.Informer

	// add and delete are functions to be invoked when services are added/removed
	add NotifyFunc
	del NotifyFunc
}

// NewServiceWatcher creates a new service watcher using the manager's cache
func NewServiceWatcher(cache ctrlcache.Cache) *ServiceWatcher {
	return &ServiceWatcher{
		cache:    cache,
		informer: nil,
	}
}

var serviceGVK = corev1.SchemeGroupVersion.WithKind("Service")

func (sw *ServiceWatcher) Start(ctx context.Context) (err error) {
	watcherLog.Info("starting service watcher")

	sw.informer, err = sw.cache.GetInformerForKind(ctx, serviceGVK)
	if err != nil {
		return fmt.Errorf("error while instantiating informer: %w", err)
	}
	sw.informer.AddEventHandler(&serviceWatcherHandler{sw: sw})

	watcherLog.Info("stopped service watcher")
	return nil
}

func (sw *ServiceWatcher) SetAddHandler(fn NotifyFunc) {
	sw.add = fn
}

func (sw *ServiceWatcher) SetDelHandler(fn NotifyFunc) {
	sw.del = fn
}

func (sw *ServiceWatcher) callAdd(svc *corev1.Service) {
	if sw.add == nil {
		return
	}

	err := retry.OnError(
		retry.DefaultRetry,
		func(e error) bool { return true },
		func() error { return sw.add(svc) },
	)
	if err != nil {
		watcherLog.Error(err,
			"error while calling add handler for service",
			"namespace", svc.Namespace,
			"name", svc.Name,
		)
	}
}

func (sw *ServiceWatcher) callDel(svc *corev1.Service) {
	if sw.del == nil {
		return
	}

	err := retry.OnError(
		retry.DefaultRetry,
		func(e error) bool { return true },
		func() error { return sw.del(svc) },
	)
	if err != nil {
		watcherLog.Error(err,
			"error while calling delete handler for service",
			"namespace", svc.Namespace,
			"name", svc.Name,
		)
	}
}

type serviceWatcherHandler struct {
	sw *ServiceWatcher
}

func (swh *serviceWatcherHandler) OnAdd(obj interface{}, isInInitialList bool) {
	svc := obj.(*corev1.Service)
	watcherLog.Info("service added", "namespace", svc.Namespace, "name", svc.Name, "initial", isInInitialList)
	swh.sw.callAdd(svc)
}

func (swh *serviceWatcherHandler) OnUpdate(oldObj, newObj interface{}) {
	oldSvc := oldObj.(*corev1.Service)
	newSvc := newObj.(*corev1.Service)
	watcherLog.Info("service updated", "namespace", oldSvc.Namespace, "name", oldSvc.Name)

	swh.sw.callDel(oldSvc)
	swh.sw.callAdd(newSvc)
}

func (swh *serviceWatcherHandler) OnDelete(obj interface{}) {
	svc := obj.(*corev1.Service)
	watcherLog.Info("service deleted", "namespace", svc.Namespace, "name", svc.Name)
	swh.sw.callDel(svc)
}
