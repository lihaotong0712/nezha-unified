package cloudflare

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/nezhahq/nezha/internal/dns"
	"golang.org/x/net/idna"
)

var writableTypes = map[string]struct{}{
	"A": {}, "AAAA": {}, "CAA": {}, "CNAME": {}, "DS": {}, "DNSKEY": {},
	"HTTPS": {}, "LOC": {}, "MX": {}, "NS": {}, "SRV": {}, "SVCB": {},
	"TLSA": {}, "TXT": {}, "URI": {},
}

type apiRecord struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Name     string          `json:"name"`
	Content  string          `json:"content"`
	TTL      uint32          `json:"ttl"`
	Proxied  *bool           `json:"proxied"`
	Comment  *string         `json:"comment"`
	Priority *uint16         `json:"priority"`
	Data     json.RawMessage `json:"data"`
	Tags     []string        `json:"tags"`
	Settings json.RawMessage `json:"settings"`
}

func (r apiRecord) record(zone dns.Zone) (dns.Record, error) {
	if !validID(r.ID) || strings.TrimSpace(r.Type) == "" {
		return dns.Record{}, errors.New("Cloudflare record has no valid ID or type")
	}
	name, err := normalizeFQDN(r.Name)
	if err != nil {
		return dns.Record{}, err
	}
	if !nameInZone(name, zone.Name) {
		return dns.Record{}, errors.New("Cloudflare record name is outside zone")
	}
	typ := strings.ToUpper(r.Type)
	if r.TTL == 0 {
		return dns.Record{}, errors.New("Cloudflare record has zero TTL")
	}
	ttl := dns.TTL{Mode: dns.TTLExplicit, Seconds: r.TTL}
	if r.TTL == 1 {
		ttl = dns.TTL{Mode: dns.TTLAutomatic}
	}
	value := r.Content
	switch typ {
	case "TXT":
		// Cloudflare returns a complete presentation string for TXT in normal
		// responses. Older endpoints occasionally omit quotes for one chunk;
		// add only that missing wrapper and preserve multi-chunk values verbatim.
		if !strings.HasPrefix(strings.TrimSpace(value), "\"") {
			value = strconv.Quote(value)
		}
	case "MX":
		priority := uint16(0)
		if r.Priority != nil {
			priority = *r.Priority
		}
		value = strconv.FormatUint(uint64(priority), 10) + " " + ensureTrailingDot(value)
	case "SRV":
		var data struct {
			Priority uint16 `json:"priority"`
			Weight   uint16 `json:"weight"`
			Port     uint16 `json:"port"`
			Target   string `json:"target"`
		}
		if len(r.Data) == 0 || string(r.Data) == "null" {
			return dns.Record{}, errors.New("Cloudflare SRV record has no structured data")
		}
		if err := json.Unmarshal(r.Data, &data); err != nil {
			return dns.Record{}, fmt.Errorf("invalid Cloudflare SRV data: %w", err)
		}
		value = fmt.Sprintf("%d %d %d %s", data.Priority, data.Weight, data.Port, ensureTrailingDot(data.Target))
	case "CNAME", "NS", "PTR":
		value = ensureTrailingDot(value)
	}
	extensions := make(map[string]json.RawMessage)
	if r.Tags != nil {
		encoded, _ := json.Marshal(r.Tags)
		extensions["tags"] = encoded
	}
	if len(r.Settings) > 0 && string(r.Settings) != "null" {
		extensions["settings"] = append(json.RawMessage(nil), r.Settings...)
	}
	return dns.Record{ID: dns.RecordID(r.ID), RecordData: dns.RecordData{
		Name: name, Type: typ, Value: value, TTL: ttl, Proxied: r.Proxied, Comment: r.Comment, Extensions: extensions,
	}}, nil
}

func recordBody(zone dns.Zone, data dns.RecordData, update bool) (map[string]any, error) {
	if err := validateZone(zone); err != nil {
		return nil, err
	}
	name, typ, err := normalizeRecordData(zone, data)
	if err != nil {
		return nil, err
	}
	if data.Line != "" {
		return nil, unsupported("Cloudflare does not support DNS record lines")
	}
	if data.Weight != nil {
		return nil, unsupported("Cloudflare does not support generic record weight")
	}
	if data.Disabled != nil {
		return nil, unsupported("Cloudflare does not expose a native disabled record state")
	}
	if _, ok := writableTypes[typ]; !ok {
		return nil, unsupported("Cloudflare record type is not supported by this adapter")
	}
	if data.Proxied != nil {
		switch typ {
		case "A", "AAAA", "CNAME":
		default:
			return nil, unsupported("Cloudflare proxying is supported only for A, AAAA and CNAME records")
		}
	}
	ttl, err := encodeTTL(data.TTL)
	if err != nil {
		return nil, err
	}
	if data.Proxied != nil && *data.Proxied && data.TTL.Mode != dns.TTLAutomatic {
		return nil, unsupported("Cloudflare proxied records require automatic TTL")
	}
	body := map[string]any{
		"name": apiName(name),
		"type": typ,
		"ttl":  ttl,
	}
	if update || data.Comment != nil {
		if data.Comment == nil {
			body["comment"] = nil
		} else {
			body["comment"] = *data.Comment
		}
	}
	if data.Proxied != nil {
		body["proxied"] = *data.Proxied
	}
	if err := validateExtensions(data.Extensions); err != nil {
		return nil, err
	}
	for key, value := range data.Extensions {
		var decoded any
		if err := json.Unmarshal(value, &decoded); err != nil {
			return nil, invalid(fmt.Sprintf("extension %q is not valid JSON", key))
		}
		body[key] = decoded
	}
	switch typ {
	case "MX":
		priority, target, err := parseMX(data.Value)
		if err != nil {
			return nil, err
		}
		body["content"] = apiTarget(target)
		body["priority"] = priority
	case "SRV":
		value, err := parseSRV(data.Value)
		if err != nil {
			return nil, err
		}
		body["data"] = map[string]any{
			"priority": value.Priority,
			"weight":   value.Weight,
			"port":     value.Port,
			"target":   apiTarget(value.Target),
		}
	default:
		body["content"] = data.Value
	}
	return body, nil
}

func encodeTTL(ttl dns.TTL) (uint32, error) {
	switch ttl.Mode {
	case dns.TTLAutomatic:
		if ttl.Seconds != 0 {
			return 0, invalid("automatic TTL must have zero seconds")
		}
		return 1, nil
	case dns.TTLExplicit:
		if ttl.Seconds == 0 {
			return 0, invalid("explicit TTL must be positive")
		}
		return ttl.Seconds, nil
	default:
		return 0, invalid("TTL mode is required")
	}
}

type srvValue struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

func parseMX(value string) (uint16, string, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 {
		return 0, "", invalid("MX value must be '<priority> <target>'")
	}
	priority, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return 0, "", invalid("MX priority must be between 0 and 65535")
	}
	return uint16(priority), parts[1], nil
}

func parseSRV(value string) (srvValue, error) {
	parts := strings.Fields(value)
	if len(parts) != 4 {
		return srvValue{}, invalid("SRV value must be '<priority> <weight> <port> <target>'")
	}
	fields := [3]uint64{}
	for i := range fields {
		parsed, err := strconv.ParseUint(parts[i], 10, 16)
		if err != nil {
			return srvValue{}, invalid("SRV numeric fields must be between 0 and 65535")
		}
		fields[i] = parsed
	}
	return srvValue{Priority: uint16(fields[0]), Weight: uint16(fields[1]), Port: uint16(fields[2]), Target: parts[3]}, nil
}

func validateExtensions(extensions map[string]json.RawMessage) error {
	for key, value := range extensions {
		if key != "tags" && key != "settings" {
			return unsupported(fmt.Sprintf("Cloudflare extension %q is not supported", key))
		}
		if !json.Valid(value) {
			return invalid(fmt.Sprintf("extension %q is not valid JSON", key))
		}
		if key == "tags" {
			var tags []string
			if err := json.Unmarshal(value, &tags); err != nil {
				return invalid("Cloudflare tags extension must be an array of strings")
			}
		}
	}
	return nil
}

func normalizeRecordData(zone dns.Zone, data dns.RecordData) (string, string, error) {
	name, err := normalizeFQDN(data.Name)
	if err != nil {
		return "", "", err
	}
	if !nameInZone(name, zone.Name) {
		return "", "", invalid("record name is outside zone")
	}
	typ := strings.ToUpper(strings.TrimSpace(data.Type))
	if typ == "" {
		return "", "", invalid("record type is required")
	}
	if data.Value == "" {
		return "", "", invalid("record value is required")
	}
	return name, typ, nil
}

func normalizeFilter(filter dns.RecordFilter, zone dns.Zone) (dns.RecordFilter, error) {
	if filter.Name != "" {
		name, err := normalizeFQDN(filter.Name)
		if err != nil {
			return dns.RecordFilter{}, err
		}
		if !nameInZone(name, zone.Name) {
			return dns.RecordFilter{}, invalid("record filter name is outside zone")
		}
		filter.Name = name
	}
	filter.Type = strings.ToUpper(strings.TrimSpace(filter.Type))
	return filter, nil
}

func normalizeFQDN(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasSuffix(value, "..") || strings.ContainsAny(value, " \t\r\n") {
		return "", invalid("invalid DNS name")
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", invalid("invalid DNS name")
	}
	labels := strings.Split(value, ".")
	for i, label := range labels {
		if label == "" {
			return "", invalid("invalid DNS name")
		}
		if strings.HasPrefix(label, "_") {
			// Service-discovery names such as _acme-challenge are legal DNS
			// owner names even though IDNA does not accept the underscore.
			labels[i] = strings.ToLower(label)
			continue
		}
		ascii, err := idna.Lookup.ToASCII(label)
		if err != nil {
			return "", invalid("invalid DNS name")
		}
		labels[i] = strings.ToLower(ascii)
	}
	return strings.Join(labels, ".") + ".", nil
}

func validateZone(zone dns.Zone) error {
	if !validID(string(zone.ID)) {
		return invalid("zone ID is required")
	}
	name, err := normalizeFQDN(zone.Name)
	if err != nil {
		return err
	}
	if name != zone.Name {
		return invalid("zone name must be a lowercase ASCII FQDN with trailing dot")
	}
	return nil
}

func nameInZone(name, zone string) bool {
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func recordMatches(record dns.Record, filter dns.RecordFilter) bool {
	return (filter.Name == "" || record.Name == filter.Name) &&
		(filter.Type == "" || record.Type == filter.Type) &&
		(filter.Line == "" || record.Line == filter.Line)
}

func recordsEqual(a, b dns.Record) bool {
	return a.ID == b.ID && a.Name == b.Name && a.Type == b.Type && a.Value == b.Value && a.TTL == b.TTL && a.Line == b.Line &&
		reflect.DeepEqual(a.Weight, b.Weight) && reflect.DeepEqual(a.Proxied, b.Proxied) && reflect.DeepEqual(a.Disabled, b.Disabled) &&
		reflect.DeepEqual(a.Comment, b.Comment) && extensionMapsEqual(a.Extensions, b.Extensions)
}

func extensionMapsEqual(a, b map[string]json.RawMessage) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func apiName(name string) string     { return strings.TrimSuffix(name, ".") }
func apiTarget(target string) string { return strings.TrimSuffix(target, ".") }
func ensureTrailingDot(value string) string {
	if value != "" && !strings.HasSuffix(value, ".") {
		return value + "."
	}
	return value
}
