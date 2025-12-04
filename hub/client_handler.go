package hub

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// struct for reading claims from service account tokens
type ServiceAccountClaims struct {
	jwt.RegisteredClaims
	K8s struct {
		Namespace string `json:"namespace"`
		Pod       struct {
			Name string `json:"name"`
		} `json:"pod"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

type ClientHandler struct {
	rp            *httputil.ReverseProxy
	log           *slog.Logger
	tokenParser   *jwt.Parser
	k8sAuthClient kubernetes.Interface
}

func NewClientHandler(rp *httputil.ReverseProxy) (*ClientHandler, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	config.Wrap(BearerTokenInjector)
	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &ClientHandler{
		rp:            rp,
		log:           slog.With("module", "HubClientHandler"),
		tokenParser:   jwt.NewParser(jwt.WithoutClaimsValidation()),
		k8sAuthClient: k8sClient,
	}, nil
}

func (ch *ClientHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path[0] != '/' {
		ch.respondError(w, r, http.StatusBadRequest, "invalid path, missing leading slash")
		return
	}
	pathParts := strings.SplitN(path, "/", 4)
	if len(pathParts) != 4 {
		ch.respondError(w, r, http.StatusBadRequest, "invalid path, expected /<kube-id>/<requested-role>/<api-path>")
		return
	}
	kubeIdentifier, requestedRemoteUser, requestedPath := pathParts[1], pathParts[2], pathParts[3]

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		ch.respondError(w, r, http.StatusUnauthorized, "missing or invalid bearer token")
		return
	}

	allowed, err := ch.checkAuth(r.Context(), authHeader[7:], kubeIdentifier, requestedRemoteUser)
	if err != nil {
		ch.respondError(w, r, http.StatusInternalServerError, fmt.Sprintf("authorization check failed: %v", err))
		return
	}
	if !allowed {
		ch.respondError(w, r, http.StatusForbidden, "insufficient permissions for requested remote user")
		return
	}

	// rewrite request
	r.URL.Path = "/" + requestedPath
	r.Header.Set("Impersonate-User", "kubeportal:"+requestedRemoteUser)
	r.Header.Del("Authorization")
	r.Host = kubeIdentifier
	r.URL.Host = kubeIdentifier

	// Set up tracing to capture connection info
	start := time.Now()
	tracer := &clientTracer{}
	wrappedWriter := &responseStatusRecorder{ResponseWriter: w}
	ch.rp.ServeHTTP(wrappedWriter, r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
		GotConn: tracer.recordConnID,
	})))
	ch.log.With(
		"kubeIdentifier", kubeIdentifier,
		"requestedRemoteUser", requestedRemoteUser,
		"connID", tracer.connID,
		"client", r.RemoteAddr,
		"method", r.Method,
		"path", r.URL.Path,
		"statusCode", wrappedWriter.statusCode,
		"duration", time.Since(start).Milliseconds(),
	).Info("Request proxied")
}

func (ch *ClientHandler) checkAuth(ctx context.Context, bearerToken, kubeIdentifier, requestedRemoteUser string) (bool, error) {
	var claims ServiceAccountClaims
	if _, _, err := ch.tokenParser.ParseUnverified(bearerToken, &claims); err != nil {
		return false, fmt.Errorf("failed to parse bearer token: %w", err)
	}

	ctx = ContextWithBearerToken(ctx, bearerToken)

	result, err := ch.k8sAuthClient.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace: claims.K8s.Namespace,
				Verb:      "use",
				Group:     "kubeportal.ibm.com",
				Version:   "v1",
				Resource:  "remoteUsers",
				Name:      requestedRemoteUser,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to perform SubjectAccessReview: %w", err)
	}

	ch.log.With(
		"kubeIdentifier", kubeIdentifier, "requestedRole", requestedRemoteUser,
		"namespace", claims.K8s.Namespace, "pod", claims.K8s.Pod.Name, "serviceAccount", claims.K8s.ServiceAccount.Name,
		"allowed", result.Status.Allowed, "denied", result.Status.Denied, "reason", result.Status.Reason,
	).Debug("Authorization check completed")

	return result.Status.Allowed, nil
}

func (ch *ClientHandler) respondError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	http.Error(w, msg, code)
	ch.log.With(
		"client", r.RemoteAddr,
		"method", r.Method,
		"path", r.URL.Path,
	).Warn(fmt.Sprintf("Request error: %d %s", code, msg))
}
