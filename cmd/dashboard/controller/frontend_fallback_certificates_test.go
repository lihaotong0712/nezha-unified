package controller

import (
	"net/http"
	"strings"
	"testing"
)

func TestFallbackToFrontendCertificateRoutesReturn200(t *testing.T) {
	t.Chdir(t.TempDir())
	router := newFrontendFallbackTestRouter(t)

	routes := []string{
		"/dashboard/certificates",
		"/dashboard/certificates/cert-42",
		"/dashboard/certificates/workflows",
		"/dashboard/certificates/workflows/workflow-42/design",
		"/dashboard/certificates/workflows/workflow-42/runs",
		"/dashboard/certificates/presets",
	}
	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			w := performFrontendFallbackRequest(t, router, route)
			if w.Code != http.StatusOK {
				t.Fatalf("%s fallback status = %d, want 200", route, w.Code)
			}
			if !strings.Contains(w.Body.String(), "admin index") {
				t.Fatalf("%s must serve admin index.html, got %q", route, w.Body.String())
			}
		})
	}
}

func TestFallbackToFrontendDoesNotWidenCertificateRoutes(t *testing.T) {
	t.Chdir(t.TempDir())
	router := newFrontendFallbackTestRouter(t)

	for _, route := range []string{
		"/dashboard/certificates/",
		"/dashboard/certificates/workflows/workflow-42/unknown",
		"/dashboard/certificates/workflows/workflow-42/design/extra",
	} {
		t.Run(route, func(t *testing.T) {
			w := performFrontendFallbackRequest(t, router, route)
			if w.Code != http.StatusNotFound {
				t.Fatalf("%s fallback status = %d, want 404", route, w.Code)
			}
		})
	}
}
