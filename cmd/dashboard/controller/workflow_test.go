package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/nezhahq/nezha/internal/audit"
	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/workflow"
	"github.com/nezhahq/nezha/model"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func workflowHTTPStore(t *testing.T) *workflow.GORMStore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	require.NoError(t, err)
	store, err := workflow.NewGORMStore(db)
	require.NoError(t, err)
	return store
}

type workflowHTTPAudit struct{}

func (workflowHTTPAudit) Record(context.Context, audit.Event) error { return nil }

type workflowHTTPAllowAuthorizer struct{}

func (workflowHTTPAllowAuthorizer) Authorize(context.Context, authz.Request) (authz.Decision, error) {
	return authz.Decision{Allowed: true, PolicyVersion: "workflow-http-test"}, nil
}

func TestWorkflowHTTPHandlersLifecycleAndStaticRoutePrecedence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	SetWorkflowService(workflow.NewService(workflowHTTPStore(t), workflowHTTPAllowAuthorizer{}, workflowHTTPAudit{}))
	t.Cleanup(func() { SetWorkflowService(nil) })

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(model.CtxKeyAuthorizedUser, &model.User{Common: model.Common{ID: 7}, Role: model.RoleMember})
		c.Next()
	})
	// Keep the dynamic certificate route after the workflow routes. Gin must
	// dispatch /certificates/workflows to the static workflow route.
	r.GET("/certificates/workflows", commonHandler(listWorkflows))
	r.POST("/certificates/workflows", commonHandler(createWorkflow))
	r.GET("/certificates/workflows/:id", commonHandler(getWorkflow))
	r.GET("/certificates/workflows/:id/versions", commonHandler(listWorkflowVersions))
	r.POST("/certificates/workflows/:id/versions", commonHandler(saveWorkflowVersion))
	r.POST("/certificates/workflows/:id/publish", commonHandler(publishWorkflow))
	r.POST("/certificates/workflows/:id/state", commonHandler(setWorkflowState))
	r.POST("/certificates/workflows/:id/runs", commonHandler(startWorkflowRun))
	r.GET("/certificates/workflows/:id/runs", commonHandler(listWorkflowRuns))
	r.GET("/certificates/workflow-runs/:id", commonHandler(getWorkflowRun))
	r.POST("/certificates/workflow-runs/:id/transition", commonHandler(transitionWorkflowRun))
	r.DELETE("/certificates/workflows/:id", commonHandler(deleteWorkflow))
	r.GET("/certificates/:id", func(c *gin.Context) {
		c.JSON(http.StatusTeapot, gin.H{"certificate_id": c.Param("id")})
	})

	call := func(method, path string, body any, out any) {
		t.Helper()
		var payload *bytes.Reader
		if body == nil {
			payload = bytes.NewReader(nil)
		} else {
			encoded, err := json.Marshal(body)
			require.NoError(t, err)
			payload = bytes.NewReader(encoded)
		}
		req := httptest.NewRequest(method, path, payload)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		r.ServeHTTP(response, req)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), out), response.Body.String())
	}

	var created model.CommonResponse[workflow.Workflow]
	call(http.MethodPost, "/certificates/workflows", map[string]any{
		"name":       "renew-production",
		"definition": map[string]any{"nodes": []any{"issue"}},
	}, &created)
	require.True(t, created.Success)
	require.Equal(t, uint64(7), created.Data.OwnerID)
	id := created.Data.Ref.ID

	var listed model.CommonResponse[[]workflow.Workflow]
	call(http.MethodGet, "/certificates/workflows", nil, &listed)
	require.True(t, listed.Success)
	require.Len(t, listed.Data, 1)

	var saved model.CommonResponse[workflow.Version]
	call(http.MethodPost, "/certificates/workflows/"+id+"/versions", map[string]any{
		"definition": map[string]any{"nodes": []any{"issue", "deploy"}},
	}, &saved)
	require.True(t, saved.Success)
	require.Equal(t, uint64(2), saved.Data.Number)

	var published model.CommonResponse[workflow.Workflow]
	call(http.MethodPost, "/certificates/workflows/"+id+"/publish", map[string]any{"version": 2}, &published)
	require.True(t, published.Success)
	require.Equal(t, workflow.StateActive, published.Data.State)
	require.Equal(t, uint64(2), published.Data.CurrentVersion)

	var started model.CommonResponse[workflow.Run]
	call(http.MethodPost, "/certificates/workflows/"+id+"/runs", nil, &started)
	require.True(t, started.Success)
	require.Equal(t, workflow.RunPending, started.Data.State)
	require.Equal(t, uint64(2), started.Data.Version)
	require.JSONEq(t, `{"nodes":["issue","deploy"]}`, string(started.Data.Definition))

	var running model.CommonResponse[workflow.Run]
	call(http.MethodPost, "/certificates/workflow-runs/"+started.Data.Ref.ID+"/transition", map[string]any{"state": workflow.RunRunning}, &running)
	require.True(t, running.Success)
	require.NotNil(t, running.Data.StartedAt)

	var canceled model.CommonResponse[workflow.Run]
	call(http.MethodPost, "/certificates/workflow-runs/"+started.Data.Ref.ID+"/transition", map[string]any{"state": workflow.RunCanceled}, &canceled)
	require.True(t, canceled.Success)
	require.NotNil(t, canceled.Data.FinishedAt)

	var disabled model.CommonResponse[workflow.Workflow]
	call(http.MethodPost, "/certificates/workflows/"+id+"/state", map[string]any{"state": workflow.StateDisabled}, &disabled)
	require.True(t, disabled.Success)
	require.Equal(t, workflow.StateDisabled, disabled.Data.State)
	var enabled model.CommonResponse[workflow.Workflow]
	call(http.MethodPost, "/certificates/workflows/"+id+"/state", map[string]any{"state": workflow.StateActive}, &enabled)
	require.True(t, enabled.Success)
	require.Equal(t, workflow.StateActive, enabled.Data.State)

	response := httptest.NewRecorder()
	r.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/certificates/workflows", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.NotEqual(t, http.StatusTeapot, response.Code)

	var deleted model.CommonResponse[any]
	call(http.MethodDelete, "/certificates/workflows/"+id, nil, &deleted)
	require.True(t, deleted.Success)
}
