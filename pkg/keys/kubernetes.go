package keys

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Labels and annotations that turn a Secret into an API key.
const (
	LabelAPIKey            = "istio-key-auth.io/api-key"
	DataKey                = "api-key"
	AnnotationClient       = "istio-key-auth.io/client"
	AnnotationHosts        = "istio-key-auth.io/hosts"
	AnnotationPathPrefixes = "istio-key-auth.io/path-prefixes"
	AnnotationMethods      = "istio-key-auth.io/methods"
	AnnotationGroups       = "istio-key-auth.io/groups"
	AnnotationExpiresAt    = "istio-key-auth.io/expires-at"
)

// KeysFromSecret reads the keys and their client from a Secret labelled LabelAPIKey=true. Every data entry named
// api-key or api-key-<suffix> is a key of the same client, so a new key can be added before the old one is removed.
func KeysFromSecret(s *corev1.Secret) (map[string]Client, error) {
	name := s.Annotations[AnnotationClient]
	if name == "" {
		name = s.Name
	}
	c := Client{
		Name:         name,
		Hosts:        splitList(s.Annotations[AnnotationHosts]),
		PathPrefixes: splitList(s.Annotations[AnnotationPathPrefixes]),
		Methods:      splitList(s.Annotations[AnnotationMethods]),
		Groups:       splitList(s.Annotations[AnnotationGroups]),
	}
	if v := strings.TrimSpace(s.Annotations[AnnotationExpiresAt]); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, fmt.Errorf("secret %s/%s: %s is not RFC 3339: %w", s.Namespace, s.Name, AnnotationExpiresAt, err)
		}
		c.ExpiresAt = t
	}
	names := make([]string, 0, len(s.Data))
	for k := range s.Data {
		if k == DataKey || strings.HasPrefix(k, DataKey+"-") {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	keys := map[string]Client{}
	for _, k := range names {
		if key := strings.TrimSpace(string(s.Data[k])); key != "" {
			keys[key] = c
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("secret %s/%s has no %q or %q entry", s.Namespace, s.Name, DataKey, DataKey+"-<suffix>")
	}
	return keys, nil
}

func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// WatchSecrets keeps store in step with the labelled Secrets in namespace ("" watches every namespace). It returns
// once the first full list is loaded, so the server never starts with an empty store by accident.
func WatchSecrets(ctx context.Context, client kubernetes.Interface, namespace string, store *Store, log *slog.Logger) error {
	factory := informers.NewSharedInformerFactoryWithOptions(client, 10*time.Minute,
		informers.WithNamespace(namespace),
		informers.WithTweakListOptions(func(o *v1.ListOptions) { o.LabelSelector = LabelAPIKey + "=true" }))
	informer := factory.Core().V1().Secrets().Informer()
	sourceOf := func(s *corev1.Secret) string { return s.Namespace + "/" + s.Name }
	upsert := func(obj any) {
		s, ok := obj.(*corev1.Secret)
		if !ok {
			return
		}
		keys, err := KeysFromSecret(s)
		if err != nil {
			log.Warn("ignoring api key secret", "secret", sourceOf(s), "error", err)
			store.Delete(sourceOf(s))
			return
		}
		store.Set(sourceOf(s), keys)
		log.Info("api keys loaded", "secret", sourceOf(s), "keys", len(keys))
	}
	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    upsert,
		UpdateFunc: func(_, obj any) { upsert(obj) },
		DeleteFunc: func(obj any) {
			if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = tomb.Obj
			}
			if s, ok := obj.(*corev1.Secret); ok {
				store.Delete(sourceOf(s))
				log.Info("api key removed", "secret", sourceOf(s))
			}
		},
	})
	if err != nil {
		return err
	}
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return fmt.Errorf("secrets did not sync")
	}
	return nil
}
