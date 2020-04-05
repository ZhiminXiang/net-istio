/*
Copyright 2019 The Knative Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package resources

import (
	"context"
	"fmt"
	"hash/adler32"
	"sort"
	"strings"

	istiov1alpha3 "istio.io/api/networking/v1alpha3"
	"istio.io/client-go/pkg/apis/networking/v1alpha3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"knative.dev/net-istio/pkg/reconciler/ingress/config"
	"knative.dev/pkg/kmeta"
	"knative.dev/serving/pkg/apis/networking/v1alpha1"
	"knative.dev/serving/pkg/network"
)

var httpServerPortName = "http-server"

// Istio Gateway requires to have at least one server. This placeholderServer is used when
// all of the real servers are deleted.
var placeholderServer = istiov1alpha3.Server{
	Hosts: []string{"place-holder.place-holder"},
	Port: &istiov1alpha3.Port{
		Name:     "place-holder",
		Number:   9999,
		Protocol: "HTTP",
	},
}

// GetServers gets the `Servers` from `Gateway` that belongs to the given Ingress.
func GetServers(gateway *v1alpha3.Gateway, ing *v1alpha1.Ingress) []*istiov1alpha3.Server {
	servers := []*istiov1alpha3.Server{}
	for i := range gateway.Spec.Servers {
		if belongsToIngress(gateway.Spec.Servers[i], ing) {
			servers = append(servers, gateway.Spec.Servers[i])
		}
	}
	return SortServers(servers)
}

// GetHTTPServer gets the HTTP `Server` from `Gateway`.
func GetHTTPServer(gateway *v1alpha3.Gateway) *istiov1alpha3.Server {
	for _, server := range gateway.Spec.Servers {
		// The server with "http" port is the default HTTP server.
		if server.Port.Name == httpServerPortName || server.Port.Name == "http" {
			return server
		}
	}
	return nil
}

// GetExistingServers gets the `Servers` from `Gateway` that have the same port name of the desired `Servers`.
func GetExistingServers(gateway *v1alpha3.Gateway, desired []*istiov1alpha3.Server) []*istiov1alpha3.Server {
	portNames := sets.String{}
	for _, s := range desired {
		portNames.Insert(s.Port.GetName())
	}
	servers := []*istiov1alpha3.Server{}
	for i := range gateway.Spec.Servers {
		if portNames.Has(gateway.Spec.Servers[i].GetPort().GetName()) {
			servers = append(servers, gateway.Spec.Servers[i])
		}
	}
	return SortServers(servers)
}

func belongsToIngress(server *istiov1alpha3.Server, ing *v1alpha1.Ingress) bool {
	// The format of the portName should be "<namespace>/<ingress_name>:<number>".
	// For example, default/routetest:0.
	portNameSplits := strings.Split(server.Port.Name, ":")
	if len(portNameSplits) != 2 {
		return false
	}
	return portNameSplits[0] == ing.GetNamespace()+"/"+ing.GetName()
}

// SortServers sorts `Server` according to its port name.
func SortServers(servers []*istiov1alpha3.Server) []*istiov1alpha3.Server {
	sort.Slice(servers, func(i, j int) bool {
		return strings.Compare(servers[i].Port.Name, servers[j].Port.Name) < 0
	})
	return servers
}

// GatewayName create a name for the Gateway that is built based on the given Ingress and bonds to the
// given ingress gateway service.
func GatewayName(accessor kmeta.Accessor, gatewaySvc *corev1.Service) string {
	gatewayServiceKey := fmt.Sprintf("%s/%s", gatewaySvc.Namespace, gatewaySvc.Name)
	return fmt.Sprintf("%s-%d", accessor.GetName(), adler32.Checksum([]byte(gatewayServiceKey)))
}

// MakeTLSServers creates the expected Gateway TLS `Servers` based on the given Ingress.
func MakeTLSServers(ing *v1alpha1.Ingress, gatewayServiceNamespace string, originSecrets map[string]*corev1.Secret) ([]*istiov1alpha3.Server, []*istiov1alpha3.Server, error) {
	ingressServers := []*istiov1alpha3.Server{}
	wildcardServers := []*istiov1alpha3.Server{}
	// TODO(zhiminx): for the hosts that does not included in the IngressTLS but listed in the IngressRule,
	// do we consider them as hosts for HTTP?
	for i, tls := range ing.Spec.TLS {
		originSecret, ok := originSecrets[secretKey(tls)]
		if !ok {
			return nil, nil, fmt.Errorf("unable to get the original secret %s/%s", tls.SecretNamespace, tls.SecretName)
		}

		certHosts, err := GetHostsFromCertSecret(originSecret)
		if err != nil {
			return nil, nil, err
		}
		isWildcard, err := IsWildcardHost(certHosts[0])
		if err != nil {
			return nil, nil, err
		}

		if isWildcard {
			// For wildcard cert, we use wildcard hosts. And we make port name independent with Ingress so that
			// the Istio Server could be reused by Ingresses that share the same cert.
			wildcardServers = append(wildcardServers, makeServer(certHosts, originSecret.Name, wildcardPortName(certHosts[0])))
		} else {
			// If the origin secret is not in the target namespace, then it should have been
			// copied into the target namespace. So we use the name of the copy.
			credentialName := tls.SecretName
			if tls.SecretNamespace != gatewayServiceNamespace {
				credentialName = targetSecret(originSecret, ing)
			}
			ingressServers = append(ingressServers, makeServer(tls.Hosts, credentialName, ingressPortName(ing, i)))
		}
	}
	return SortServers(ingressServers), SortServers(wildcardServers), nil
}

func ingressPortName(ing *v1alpha1.Ingress, index int) string {
	return fmt.Sprintf("%s/%s:%d", ing.GetNamespace(), ing.GetName(), index)
}

func wildcardPortName(wildcardHost string) string {
	splits := strings.SplitN(wildcardHost, ".", 2)
	return splits[1]
}

func makeServer(hosts []string, credentialName, port string) *istiov1alpha3.Server {
	return &istiov1alpha3.Server{
		Hosts: hosts,
		Port: &istiov1alpha3.Port{
			Name:     port,
			Number:   443,
			Protocol: "HTTPS",
		},
		Tls: &istiov1alpha3.Server_TLSOptions{
			Mode:              istiov1alpha3.Server_TLSOptions_SIMPLE,
			ServerCertificate: corev1.TLSCertKey,
			PrivateKey:        corev1.TLSPrivateKeyKey,
			CredentialName:    credentialName,
		},
	}
}

// MakeHTTPServer creates a HTTP Gateway `Server` based on the HTTPProtocol
// configuration.
func MakeHTTPServer(httpProtocol network.HTTPProtocol, hosts []string) *istiov1alpha3.Server {
	if httpProtocol == network.HTTPDisabled {
		return nil
	}
	server := &istiov1alpha3.Server{
		Hosts: hosts,
		Port: &istiov1alpha3.Port{
			Name:     httpServerPortName,
			Number:   80,
			Protocol: "HTTP",
		},
	}
	if httpProtocol == network.HTTPRedirected {
		server.Tls = &istiov1alpha3.Server_TLSOptions{
			HttpsRedirect: true,
		}
	}
	return server
}

// ServiceNamespaceFromURL extracts the namespace part from the service URL.
// TODO(nghia):  Remove this by parsing at config parsing time.
func ServiceNamespaceFromURL(svc string) (string, error) {
	parts := strings.SplitN(svc, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("unexpected service URL form: %s", svc)
	}
	return parts[1], nil
}

// TODO(nghia):  Remove this by parsing at config parsing time.
// GetIngressGatewaySvcNameNamespaces gets the Istio ingress namespaces from ConfigMap.
func GetIngressGatewaySvcNameNamespaces(ctx context.Context) ([]metav1.ObjectMeta, error) {
	cfg := config.FromContext(ctx).Istio
	nameNamespaces := make([]metav1.ObjectMeta, len(cfg.IngressGateways))
	for i, ingressgateway := range cfg.IngressGateways {
		parts := strings.SplitN(ingressgateway.ServiceURL, ".", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("unexpected service URL form: %s", ingressgateway.ServiceURL)
		}
		nameNamespaces[i] = metav1.ObjectMeta{
			Name:      parts[0],
			Namespace: parts[1],
		}
	}
	return nameNamespaces, nil
}

// UpdateGateway replaces the existing servers with the wanted servers.
func UpdateGateway(gateway *v1alpha3.Gateway, want []*istiov1alpha3.Server, existing []*istiov1alpha3.Server) *v1alpha3.Gateway {
	existingServers := sets.String{}
	for i := range existing {
		existingServers.Insert(existing[i].Port.Name)
	}

	servers := []*istiov1alpha3.Server{}
	for _, server := range gateway.Spec.Servers {
		// We remove
		//  1) the existing servers
		//  2) the placeholder servers.
		if existingServers.Has(server.Port.Name) || isPlaceHolderServer(server) {
			continue
		}
		servers = append(servers, server)
	}
	servers = append(servers, want...)

	// Istio Gateway requires to have at least one server. So if the final gateway does not have any server,
	// we add "placeholder" server back.
	if len(servers) == 0 {
		servers = append(servers, &placeholderServer)
	}

	SortServers(servers)
	gateway.Spec.Servers = servers
	return gateway
}

func isPlaceHolderServer(server *istiov1alpha3.Server) bool {
	return equality.Semantic.DeepEqual(server, &placeholderServer)
}
