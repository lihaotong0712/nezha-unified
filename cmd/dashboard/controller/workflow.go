package controller

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
	"github.com/nezhahq/nezha/internal/workflow"
)

var workflowServiceState struct {
	sync.RWMutex
	service *workflow.Service
}

func SetWorkflowService(service *workflow.Service) {
	workflowServiceState.Lock()
	workflowServiceState.service = service
	workflowServiceState.Unlock()
}
func currentWorkflowService() *workflow.Service {
	workflowServiceState.RLock()
	defer workflowServiceState.RUnlock()
	return workflowServiceState.service
}
func requireWorkflowService(e authz.Execution) (*workflow.Service, error) {
	s := currentWorkflowService()
	if s == nil {
		return nil, platformerr.New(platformerr.Unavailable, e.OperationID, nil)
	}
	return s, nil
}
func workflowRef(id string) (resource.Ref, error) {
	r := resource.Ref{Kind: resource.Workflow, ID: strings.TrimSpace(id)}
	if err := r.Validate(); err != nil {
		return resource.Ref{}, platformerr.New(platformerr.InvalidArgument, "", err)
	}
	return r, nil
}
func workflowRunRef(id string) (resource.Ref, error) {
	r := resource.Ref{Kind: resource.WorkflowRun, ID: strings.TrimSpace(id)}
	if err := r.Validate(); err != nil {
		return resource.Ref{}, platformerr.New(platformerr.InvalidArgument, "", err)
	}
	return r, nil
}
func listWorkflows(c *gin.Context) ([]workflow.Workflow, error) {
	e, err := certificateExecution(c)
	if err != nil {
		return nil, err
	}
	s, err := requireWorkflowService(e)
	if err != nil {
		return nil, err
	}
	return s.List(c.Request.Context(), e, getUid(c))
}
func getWorkflow(c *gin.Context) (workflow.Workflow, error) {
	e, err := certificateExecution(c)
	if err != nil {
		return workflow.Workflow{}, err
	}
	s, err := requireWorkflowService(e)
	if err != nil {
		return workflow.Workflow{}, err
	}
	r, err := workflowRef(c.Param("id"))
	if err != nil {
		return workflow.Workflow{}, withOperation(err, e.OperationID)
	}
	return s.Get(c.Request.Context(), e, r)
}

type workflowCreatePayload struct {
	Name       string          `json:"name"`
	Definition json.RawMessage `json:"definition"`
}

func createWorkflow(c *gin.Context) (workflow.Workflow, error) {
	e, err := certificateExecution(c)
	if err != nil {
		return workflow.Workflow{}, err
	}
	s, err := requireWorkflowService(e)
	if err != nil {
		return workflow.Workflow{}, err
	}
	var p workflowCreatePayload
	if err := c.ShouldBindJSON(&p); err != nil {
		return workflow.Workflow{}, platformerr.New(platformerr.InvalidArgument, e.OperationID, err)
	}
	return s.Create(c.Request.Context(), workflow.CreateRequest{Execution: e, OwnerID: getUid(c), Name: p.Name, Definition: p.Definition})
}
func listWorkflowVersions(c *gin.Context) ([]workflow.Version, error) {
	e, err := certificateExecution(c)
	if err != nil {
		return nil, err
	}
	s, err := requireWorkflowService(e)
	if err != nil {
		return nil, err
	}
	r, err := workflowRef(c.Param("id"))
	if err != nil {
		return nil, withOperation(err, e.OperationID)
	}
	return s.Versions(c.Request.Context(), e, r)
}

type workflowPublishPayload struct {
	Version uint64 `json:"version"`
}

type workflowVersionPayload struct {
	Definition json.RawMessage `json:"definition"`
}

func saveWorkflowVersion(c *gin.Context) (workflow.Version, error) {
	e, err := certificateExecution(c)
	if err != nil {
		return workflow.Version{}, err
	}
	s, err := requireWorkflowService(e)
	if err != nil {
		return workflow.Version{}, err
	}
	r, err := workflowRef(c.Param("id"))
	if err != nil {
		return workflow.Version{}, withOperation(err, e.OperationID)
	}
	var p workflowVersionPayload
	if err := c.ShouldBindJSON(&p); err != nil {
		return workflow.Version{}, platformerr.New(platformerr.InvalidArgument, e.OperationID, err)
	}
	return s.SaveVersion(c.Request.Context(), e, r, p.Definition)
}

func publishWorkflow(c *gin.Context) (workflow.Workflow, error) {
	e, err := certificateExecution(c)
	if err != nil {
		return workflow.Workflow{}, err
	}
	s, err := requireWorkflowService(e)
	if err != nil {
		return workflow.Workflow{}, err
	}
	r, err := workflowRef(c.Param("id"))
	if err != nil {
		return workflow.Workflow{}, withOperation(err, e.OperationID)
	}
	var p workflowPublishPayload
	if err := c.ShouldBindJSON(&p); err != nil {
		return workflow.Workflow{}, platformerr.New(platformerr.InvalidArgument, e.OperationID, err)
	}
	return s.Publish(c.Request.Context(), e, r, p.Version)
}

func setWorkflowState(c *gin.Context) (workflow.Workflow, error) {
	e, err := certificateExecution(c)
	if err != nil {
		return workflow.Workflow{}, err
	}
	s, err := requireWorkflowService(e)
	if err != nil {
		return workflow.Workflow{}, err
	}
	r, err := workflowRef(c.Param("id"))
	if err != nil {
		return workflow.Workflow{}, withOperation(err, e.OperationID)
	}
	var p struct {
		State workflow.State `json:"state"`
	}
	if err := c.ShouldBindJSON(&p); err != nil {
		return workflow.Workflow{}, platformerr.New(platformerr.InvalidArgument, e.OperationID, err)
	}
	return s.SetState(c.Request.Context(), e, r, p.State)
}

func deleteWorkflow(c *gin.Context) (any, error) {
	e, err := certificateExecution(c)
	if err != nil {
		return nil, err
	}
	s, err := requireWorkflowService(e)
	if err != nil {
		return nil, err
	}
	r, err := workflowRef(c.Param("id"))
	if err != nil {
		return nil, withOperation(err, e.OperationID)
	}
	if err := s.Delete(c.Request.Context(), e, r); err != nil {
		return nil, err
	}
	return nil, nil
}

func startWorkflowRun(c *gin.Context) (workflow.Run, error) {
	e, err := certificateExecution(c)
	if err != nil {
		return workflow.Run{}, err
	}
	s, err := requireWorkflowService(e)
	if err != nil {
		return workflow.Run{}, err
	}
	r, err := workflowRef(c.Param("id"))
	if err != nil {
		return workflow.Run{}, withOperation(err, e.OperationID)
	}
	return s.StartRun(c.Request.Context(), workflow.StartRunRequest{Execution: e, Workflow: r})
}
func listWorkflowRuns(c *gin.Context) ([]workflow.Run, error) {
	e, err := certificateExecution(c)
	if err != nil {
		return nil, err
	}
	s, err := requireWorkflowService(e)
	if err != nil {
		return nil, err
	}
	r, err := workflowRef(c.Param("id"))
	if err != nil {
		return nil, withOperation(err, e.OperationID)
	}
	return s.ListRuns(c.Request.Context(), e, r)
}
func getWorkflowRun(c *gin.Context) (workflow.Run, error) {
	e, err := certificateExecution(c)
	if err != nil {
		return workflow.Run{}, err
	}
	s, err := requireWorkflowService(e)
	if err != nil {
		return workflow.Run{}, err
	}
	r, err := workflowRunRef(c.Param("id"))
	if err != nil {
		return workflow.Run{}, withOperation(err, e.OperationID)
	}
	return s.GetRun(c.Request.Context(), e, r)
}
func transitionWorkflowRun(c *gin.Context) (workflow.Run, error) {
	e, err := certificateExecution(c)
	if err != nil {
		return workflow.Run{}, err
	}
	s, err := requireWorkflowService(e)
	if err != nil {
		return workflow.Run{}, err
	}
	r, err := workflowRunRef(c.Param("id"))
	if err != nil {
		return workflow.Run{}, withOperation(err, e.OperationID)
	}
	var p struct {
		State   workflow.RunState `json:"state"`
		Code    string            `json:"error_code"`
		Message string            `json:"error_message"`
	}
	if err := c.ShouldBindJSON(&p); err != nil {
		return workflow.Run{}, platformerr.New(platformerr.InvalidArgument, e.OperationID, err)
	}
	return s.TransitionRun(c.Request.Context(), e, r, p.State, p.Code, p.Message)
}

