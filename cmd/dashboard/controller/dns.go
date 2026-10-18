package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/dns"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
	"github.com/nezhahq/nezha/model"
)

var dnsServiceState struct {
	sync.RWMutex
	service *dns.Service
}

// SetDNSService injects the unified DNS service used by Dashboard handlers.
// Runtime construction owns the database, credential resolver and provider
// factory; tests may install an in-memory service explicitly.
func SetDNSService(service *dns.Service) {
	dnsServiceState.Lock()
	dnsServiceState.service = service
	dnsServiceState.Unlock()
}

func currentDNSService() *dns.Service {
	dnsServiceState.RLock()
	defer dnsServiceState.RUnlock()
	return dnsServiceState.service
}

func dnsExecution(c *gin.Context) (authz.Execution, error) {
	value, ok := c.Get(model.CtxKeyAuthorizedUser)
	user, userOK := value.(*model.User)
	if !ok || !userOK || user == nil || user.ID == 0 {
		return authz.Execution{}, platformerr.New(platformerr.Unauthenticated, "", nil)
	}
	principal := authz.User(user.ID)
	execution := authz.Execution{Subject: principal, TriggeredBy: principal, Entry: authz.Session, OperationID: certificateOperationID()}
	if token := APITokenFromContext(c); token != nil {
		execution.Entry = authz.PAT
		execution.TokenID = token.ID
	}
	if err := execution.Validate(); err != nil {
		return authz.Execution{}, platformerr.New(platformerr.Unauthenticated, execution.OperationID, err)
	}
	return execution, nil
}

func requireDNSService(execution authz.Execution) (*dns.Service, error) {
	service := currentDNSService()
	if service == nil {
		return nil, platformerr.New(platformerr.Unavailable, execution.OperationID, nil)
	}
	return service, nil
}

func dnsZoneRef(id string) (resource.Ref, error) {
	ref := resource.Ref{Kind: resource.DNSZone, ID: strings.TrimSpace(id)}
	if err := ref.Validate(); err != nil {
		return resource.Ref{}, platformerr.New(platformerr.InvalidArgument, "", err)
	}
	return ref, nil
}

func dnsRecordID(id string) (dns.RecordID, error) {
	id = strings.TrimSpace(id)
	if err := resource.ValidateOpaqueID(id); err != nil {
		return "", platformerr.New(platformerr.InvalidArgument, "", err)
	}
	return dns.RecordID(id), nil
}

func listDNSZones(c *gin.Context) ([]dns.ZoneBinding, error) {
	execution, err := dnsExecution(c)
	if err != nil {
		return nil, err
	}
	service, err := requireDNSService(execution)
	if err != nil {
		return nil, err
	}
	return service.ListZones(c.Request.Context(), execution, getUid(c))
}

func listDNSRecords(c *gin.Context) (dns.Page[dns.Record], error) {
	execution, err := dnsExecution(c)
	if err != nil {
		return dns.Page[dns.Record]{}, err
	}
	service, err := requireDNSService(execution)
	if err != nil {
		return dns.Page[dns.Record]{}, err
	}
	zone, err := dnsZoneRef(c.Param("id"))
	if err != nil {
		return dns.Page[dns.Record]{}, withOperation(err, execution.OperationID)
	}
	limit, err := dnsPageLimit(c.Query("limit"))
	if err != nil {
		return dns.Page[dns.Record]{}, platformerr.New(platformerr.InvalidArgument, execution.OperationID, err)
	}
	return service.ListRecords(c.Request.Context(), execution, zone, dns.RecordFilter{
		Name: strings.TrimSpace(c.Query("name")),
		Type: strings.ToUpper(strings.TrimSpace(c.Query("type"))),
		Line: strings.TrimSpace(c.Query("line")),
	}, dns.PageRequest{Cursor: c.Query("cursor"), Limit: limit})
}

func getDNSRecord(c *gin.Context) (dns.Record, error) {
	execution, err := dnsExecution(c)
	if err != nil {
		return dns.Record{}, err
	}
	service, err := requireDNSService(execution)
	if err != nil {
		return dns.Record{}, err
	}
	zone, err := dnsZoneRef(c.Param("id"))
	if err != nil {
		return dns.Record{}, withOperation(err, execution.OperationID)
	}
	recordID, err := dnsRecordID(c.Param("recordID"))
	if err != nil {
		return dns.Record{}, withOperation(err, execution.OperationID)
	}
	return service.GetRecord(c.Request.Context(), execution, zone, recordID)
}

func createDNSRecord(c *gin.Context) (dns.Record, error) {
	execution, err := dnsExecution(c)
	if err != nil {
		return dns.Record{}, err
	}
	service, err := requireDNSService(execution)
	if err != nil {
		return dns.Record{}, err
	}
	zone, err := dnsZoneRef(c.Param("id"))
	if err != nil {
		return dns.Record{}, withOperation(err, execution.OperationID)
	}
	data, err := decodeDNSRecordData(c)
	if err != nil {
		return dns.Record{}, platformerr.New(platformerr.InvalidArgument, execution.OperationID, err)
	}
	return service.CreateRecord(c.Request.Context(), execution, zone, data)
}

func updateDNSRecord(c *gin.Context) (dns.Record, error) {
	execution, err := dnsExecution(c)
	if err != nil {
		return dns.Record{}, err
	}
	service, err := requireDNSService(execution)
	if err != nil {
		return dns.Record{}, err
	}
	zone, err := dnsZoneRef(c.Param("id"))
	if err != nil {
		return dns.Record{}, withOperation(err, execution.OperationID)
	}
	recordID, err := dnsRecordID(c.Param("recordID"))
	if err != nil {
		return dns.Record{}, withOperation(err, execution.OperationID)
	}
	data, err := decodeDNSRecordData(c)
	if err != nil {
		return dns.Record{}, platformerr.New(platformerr.InvalidArgument, execution.OperationID, err)
	}
	before, err := service.GetRecord(c.Request.Context(), execution, zone, recordID)
	if err != nil {
		return dns.Record{}, err
	}
	return service.UpdateRecord(c.Request.Context(), execution, zone, before, data)
}

func deleteDNSRecord(c *gin.Context) (any, error) {
	execution, err := dnsExecution(c)
	if err != nil {
		return nil, err
	}
	service, err := requireDNSService(execution)
	if err != nil {
		return nil, err
	}
	zone, err := dnsZoneRef(c.Param("id"))
	if err != nil {
		return nil, withOperation(err, execution.OperationID)
	}
	recordID, err := dnsRecordID(c.Param("recordID"))
	if err != nil {
		return nil, withOperation(err, execution.OperationID)
	}
	before, err := service.GetRecord(c.Request.Context(), execution, zone, recordID)
	if err != nil {
		return nil, err
	}
	if err := service.DeleteRecord(c.Request.Context(), execution, zone, before); err != nil {
		return nil, err
	}
	return gin.H{"deleted": true, "id": recordID}, nil
}

func dnsPageLimit(raw string) (uint32, error) {
	if strings.TrimSpace(raw) == "" {
		return 100, nil
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || value == 0 || value > 1000 {
		return 0, errors.New("limit must be between 1 and 1000")
	}
	return uint32(value), nil
}

func decodeDNSRecordData(c *gin.Context) (dns.RecordData, error) {
	if !strings.HasPrefix(strings.ToLower(c.GetHeader("Content-Type")), "application/json") {
		return dns.RecordData{}, errors.New("expected application/json")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20))
	var data dns.RecordData
	if err := decoder.Decode(&data); err != nil {
		return dns.RecordData{}, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return dns.RecordData{}, fmt.Errorf("expected one DNS record object")
	}
	return data, nil
}
