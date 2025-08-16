// Copyright 2021 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"
	"encoding/json"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/fullstorydev/grpcurl"
	"github.com/jhump/protoreflect/grpcreflect"
)

type GRPCHealthCheck interface {
	Check(c context.Context, service string, method string, expected map[string]interface{}) (bool, codes.Code, *peer.Peer, string, error)
}

type gRPCHealthCheckClient struct {
	client grpc_health_v1.HealthClient
	conn   *grpc.ClientConn
}

func NewGrpcHealthCheckClient(conn *grpc.ClientConn) GRPCHealthCheck {
	client := new(gRPCHealthCheckClient)
	client.client = grpc_health_v1.NewHealthClient(conn)
	client.conn = conn
	return client
}

func (c *gRPCHealthCheckClient) Close() error {
	return c.conn.Close()
}

func (c *gRPCHealthCheckClient) checkSpecificMethod(ctx context.Context, service string, method string, expected map[string]interface{}, serverPeer *peer.Peer) (bool, codes.Code, *peer.Peer, string, error) {
	refClient := grpcreflect.NewClientAuto(ctx, c.conn)

	defer refClient.Reset()

	descSource := grpcurl.DescriptorSourceFromServer(ctx, refClient)
	services, err := refClient.ListServices()
	if err != nil {
		return false, codes.Unknown, nil, "", err
	}

	var fullServiceName string
	for _, s := range services {
		if strings.HasSuffix(s, service) {
			fullServiceName = s
			break
		}
	}
	if fullServiceName == "" {
		return false, codes.NotFound, nil, "", fmt.Errorf("service %q not found via reflection", service)
	}

	fullMethod := fullServiceName + "/" + method

	jsonReq := `{}`
	jsonReader := strings.NewReader(jsonReq)
	rf, formatter, err := grpcurl.RequestParserAndFormatter(grpcurl.Format("json"), descSource, jsonReader, grpcurl.FormatOptions{EmitJSONDefaultFields: true})
	if err != nil {
		return false, codes.Unknown, nil, "", err
	}

	var output bytes.Buffer
	eventHandler := &grpcurl.DefaultEventHandler{
		Out:       &output,
		Formatter: formatter,
	}

	err = grpcurl.InvokeRPC(ctx, descSource, c.conn, fullMethod, []string{}, eventHandler, rf.Next)
	if err != nil {
		return false, codes.Unknown, nil, "", err
	}

	respStr := output.String()

	if len(expected) > 0 {
		var respJSON map[string]interface{}
		if err := json.Unmarshal([]byte(respStr), &respJSON); err != nil {
			return false, codes.Unknown, serverPeer, respStr, fmt.Errorf("failed to parse response JSON: %v", err)
		}

		for key, val := range expected {
			if respVal, ok := respJSON[key]; !ok || respVal != val {
				return false, codes.Unknown, serverPeer, respStr, fmt.Errorf("expected field %q=%v, got %v", key, val, respVal)
			}
		}
	}

	return true, codes.OK, serverPeer, respStr, nil
}

func (c *gRPCHealthCheckClient) Check(ctx context.Context, service string, method string, expected map[string]interface{}) (bool, codes.Code, *peer.Peer, string, error) {
	serverPeer := new(peer.Peer)

	if method != "" || method != "Check" {
		// custom healthcheck
		return c.checkSpecificMethod(ctx, service, method, expected, serverPeer)
	}

	// standard healthcheck
	req := grpc_health_v1.HealthCheckRequest{Service: service}
	res, err := c.client.Check(ctx, &req, grpc.Peer(serverPeer))
	if err == nil {
		if res.GetStatus() == grpc_health_v1.HealthCheckResponse_SERVING {
			return true, codes.OK, serverPeer, res.Status.String(), nil
		}
		return false, codes.OK, serverPeer, res.Status.String(), nil
	}

	returnStatus, _ := status.FromError(err)

	return false, returnStatus.Code(), nil, "", err
}

func ProbeGRPC(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger) (success bool) {

	var (
		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_grpc_duration_seconds",
			Help: "Duration of gRPC request by phase",
		}, []string{"phase"})

		isSSLGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_grpc_ssl",
			Help: "Indicates if SSL was used for the connection",
		})

		statusCodeGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_grpc_status_code",
			Help: "Response gRPC status code",
		})

		healthCheckResponseGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_grpc_healthcheck_response",
			Help: "Response HealthCheck response",
		}, []string{"serving_status"})

		probeSSLEarliestCertExpiryGauge = prometheus.NewGauge(sslEarliestCertExpiryGaugeOpts)

		probeTLSVersion = prometheus.NewGaugeVec(
			probeTLSInfoGaugeOpts,
			[]string{"version"},
		)

		probeSSLLastInformation = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probe_ssl_last_chain_info",
				Help: "Contains SSL leaf certificate information",
			},
			[]string{"fingerprint_sha256", "subject", "issuer", "subjectalternative", "serialnumber"},
		)
	)

	for _, lv := range []string{"resolve"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	registry.MustRegister(durationGaugeVec)
	registry.MustRegister(isSSLGauge)
	registry.MustRegister(statusCodeGauge)
	registry.MustRegister(healthCheckResponseGaugeVec)

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		logger.Error("Could not parse target URL", "err", err)
		return false
	}

	targetHost, targetPort, err := net.SplitHostPort(targetURL.Host)
	// If split fails, assuming it's a hostname without port part.
	if err != nil {
		targetHost = targetURL.Host
	}

	tlsConfig, err := pconfig.NewTLSConfig(&module.GRPC.TLSConfig)
	if err != nil {
		logger.Error("Error creating TLS configuration", "err", err)
		return false
	}

	ip, lookupTime, err := chooseProtocol(ctx, module.GRPC.PreferredIPProtocol, module.GRPC.IPProtocolFallback, targetHost, registry, logger)
	if err != nil {
		logger.Error("Error resolving address", "err", err)
		return false
	}
	durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)
	checkStart := time.Now()
	if len(tlsConfig.ServerName) == 0 {
		// If there is no `server_name` in tls_config, use
		// the hostname of the target.
		tlsConfig.ServerName = targetHost
	}

	if targetPort == "" {
		targetURL.Host = "[" + ip.String() + "]"
	} else {
		targetURL.Host = net.JoinHostPort(ip.String(), targetPort)
	}

	var opts []grpc.DialOption
	target = targetHost + ":" + targetPort
	if !module.GRPC.TLS {
		logger.Debug("Dialing GRPC without TLS")
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if len(targetPort) == 0 {
			target = targetHost + ":80"
		}
	} else {
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.WithTransportCredentials(creds))
		if len(targetPort) == 0 {
			target = targetHost + ":443"
		}
	}

	conn, err := grpc.NewClient(target, opts...)

	if err != nil {
		logger.Error("did not connect", "err", err)
	}

	client := NewGrpcHealthCheckClient(conn)
	defer conn.Close()
	ok, statusCode, serverPeer, servingStatus, err := client.Check(context.Background(), module.GRPC.Service, module.GRPC.Method, module.GRPC.ExpectedResponseJSON)
	durationGaugeVec.WithLabelValues("check").Add(time.Since(checkStart).Seconds())

	for servingStatusName := range grpc_health_v1.HealthCheckResponse_ServingStatus_value {
		healthCheckResponseGaugeVec.WithLabelValues(servingStatusName).Set(float64(0))
	}
	if servingStatus != "" {
		healthCheckResponseGaugeVec.WithLabelValues(servingStatus).Set(float64(1))
	}

	if serverPeer != nil {
		tlsInfo, tlsOk := serverPeer.AuthInfo.(credentials.TLSInfo)
		if tlsOk {
			registry.MustRegister(probeSSLEarliestCertExpiryGauge, probeTLSVersion, probeSSLLastInformation)
			isSSLGauge.Set(float64(1))
			probeSSLEarliestCertExpiryGauge.Set(float64(getEarliestCertExpiry(&tlsInfo.State).Unix()))
			probeTLSVersion.WithLabelValues(getTLSVersion(&tlsInfo.State)).Set(1)
			probeSSLLastInformation.WithLabelValues(getFingerprint(&tlsInfo.State), getSubject(&tlsInfo.State), getIssuer(&tlsInfo.State), getDNSNames(&tlsInfo.State), getSerialNumber(&tlsInfo.State)).Set(1)
		} else {
			isSSLGauge.Set(float64(0))
		}
	}
	statusCodeGauge.Set(float64(statusCode))

	if !ok || err != nil {
		logger.Error("can't connect grpc server:", "err", err)
		success = false
	} else {
		logger.Debug("connect the grpc server successfully")
		success = true
	}

	return
}
