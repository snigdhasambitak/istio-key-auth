package keys

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func secret(name, key string, labelled bool) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "apps", Annotations: map[string]string{
			AnnotationClient: name + "-client", AnnotationPathPrefixes: "/v1/, /v2/",
		}},
		Data: map[string][]byte{DataKey: []byte(key)},
	}
	if labelled {
		s.Labels = map[string]string{LabelAPIKey: "true"}
	}
	return s
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("condition not met in time")
}

func TestWatchSecretsFollowsLabelledSecrets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := fake.NewSimpleClientset(secret("orders", "k1", true), secret("unrelated", "k2", false))
	store := NewStore()
	if err := WatchSecrets(ctx, client, "", store, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}

	c, ok := store.Lookup("k1")
	if !ok || c.Name != "orders-client" || len(c.PathPrefixes) != 2 {
		t.Fatalf("got %+v %v", c, ok)
	}
	if _, ok := store.Lookup("k2"); ok {
		t.Fatal("an unlabelled secret was loaded")
	}

	secrets := client.CoreV1().Secrets("apps")
	rotated := secret("orders", "k1-rotated", true)
	if _, err := secrets.Update(ctx, rotated, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { _, ok := store.Lookup("k1-rotated"); return ok })
	if _, ok := store.Lookup("k1"); ok {
		t.Fatal("the old key still works after rotation")
	}

	if err := secrets.Delete(ctx, "orders", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return store.Len() == 0 })
}

func TestKeysFromSecretRotationAndAnnotations(t *testing.T) {
	s := secret("orders", "k-old", true)
	s.Data[DataKey+"-next"] = []byte("k-new")
	s.Data["unrelated"] = []byte("not-a-key")
	s.Annotations[AnnotationMethods] = "GET, HEAD"
	s.Annotations[AnnotationGroups] = "partners"
	s.Annotations[AnnotationExpiresAt] = "2030-01-01T00:00:00Z"
	keys, err := KeysFromSecret(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys["k-old"].Name != "orders-client" || keys["k-new"].Name != "orders-client" {
		t.Fatalf("got %+v", keys)
	}
	c := keys["k-new"]
	if len(c.Methods) != 2 || c.Groups[0] != "partners" || c.ExpiresAt.Year() != 2030 {
		t.Fatalf("annotations not read: %+v", c)
	}
	s.Annotations[AnnotationExpiresAt] = "next tuesday"
	if _, err := KeysFromSecret(s); err == nil {
		t.Fatal("an invalid expiry was accepted")
	}
}
