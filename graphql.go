package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const graphqlEndpoint = "https://api.cloudflare.com/client/v4/graphql"

type GraphQLClient struct {
	httpClient *http.Client
	cfg        *Config
}

func NewGraphQLClient(cfg *Config) *GraphQLClient {
	return &GraphQLClient{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cfg:        cfg,
	}
}

type graphqlRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type graphqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (c *GraphQLClient) query(q string, vars map[string]interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(graphqlRequest{Query: q, Variables: vars})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", graphqlEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if c.cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
	} else {
		req.Header.Set("X-Auth-Key", c.cfg.APIKey)
		req.Header.Set("X-Auth-Email", c.cfg.APIEmail)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var gqlResp graphqlResponse
	if err := json.Unmarshal(respBody, &gqlResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("graphql error: %s", gqlResp.Errors[0].Message)
	}

	return gqlResp.Data, nil
}

// --- httpRequests1hGroups: pre-aggregated hourly HTTP analytics (works on all plans) ---

type HTTPRequests1hResult struct {
	Viewer struct {
		Zones []struct {
			Groups []HTTPRequests1hGroup `json:"httpRequests1hGroups"`
		} `json:"zones"`
	} `json:"viewer"`
}

type HTTPRequests1hGroup struct {
	Sum struct {
		Requests          int64              `json:"requests"`
		CachedRequests    int64              `json:"cachedRequests"`
		EncryptedRequests int64              `json:"encryptedRequests"`
		Bytes             int64              `json:"bytes"`
		CachedBytes       int64              `json:"cachedBytes"`
		EncryptedBytes    int64              `json:"encryptedBytes"`
		Threats           int64              `json:"threats"`
		PageViews         int64              `json:"pageViews"`
		CountryMap        []CountryMapEntry  `json:"countryMap"`
		ResponseStatusMap []StatusMapEntry   `json:"responseStatusMap"`
		ContentTypeMap    []ContentMapEntry  `json:"contentTypeMap"`
		BrowserMap        []BrowserMapEntry  `json:"browserMap"`
	} `json:"sum"`
	Uniq struct {
		Uniques int64 `json:"uniques"`
	} `json:"uniq"`
}

type CountryMapEntry struct {
	Country  string `json:"clientCountryName"`
	Requests int64  `json:"requests"`
	Threats  int64  `json:"threats"`
	Bytes    int64  `json:"bytes"`
}

type StatusMapEntry struct {
	Status   int   `json:"edgeResponseStatus"`
	Requests int64 `json:"requests"`
}

type ContentMapEntry struct {
	ContentType string `json:"edgeResponseContentTypeName"`
	Requests    int64  `json:"requests"`
	Bytes       int64  `json:"bytes"`
}

type BrowserMapEntry struct {
	Browser   string `json:"uaBrowserFamily"`
	PageViews int64  `json:"pageViews"`
}

func (c *GraphQLClient) FetchHTTPRequests1h(zoneID string, since, until time.Time) ([]HTTPRequests1hGroup, error) {
	q := `query ($zoneID: String!, $since: Time!, $until: Time!) {
		viewer {
			zones(filter: {zoneTag: $zoneID}) {
				httpRequests1hGroups(
					filter: {datetime_geq: $since, datetime_lt: $until}
					limit: 24
					orderBy: [datetime_DESC]
				) {
					dimensions {
						datetime
					}
					sum {
						requests
						cachedRequests
						encryptedRequests
						bytes
						cachedBytes
						encryptedBytes
						threats
						pageViews
						countryMap {
							clientCountryName
							requests
							threats
							bytes
						}
						responseStatusMap {
							edgeResponseStatus
							requests
						}
						contentTypeMap {
							edgeResponseContentTypeName
							requests
							bytes
						}
						browserMap {
							uaBrowserFamily
							pageViews
						}
					}
					uniq {
						uniques
					}
				}
			}
		}
	}`

	vars := map[string]interface{}{
		"zoneID": zoneID,
		"since":  since.Format(time.RFC3339),
		"until":  until.Format(time.RFC3339),
	}

	data, err := c.query(q, vars)
	if err != nil {
		return nil, err
	}

	var result HTTPRequests1hResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("unmarshal http requests 1h: %w", err)
	}

	if len(result.Viewer.Zones) == 0 {
		return nil, nil
	}
	return result.Viewer.Zones[0].Groups, nil
}

// --- httpRequestsAdaptiveGroups: per-request dimensions (cache, protocol, SSL) ---

type HTTPRequestsAdaptiveResult struct {
	Viewer struct {
		Zones []struct {
			Groups []HTTPRequestAdaptiveGroup `json:"httpRequestsAdaptiveGroups"`
		} `json:"zones"`
	} `json:"viewer"`
}

type HTTPRequestAdaptiveGroup struct {
	Count      int `json:"count"`
	Dimensions struct {
		CacheStatus               string `json:"cacheStatus"`
		ClientRequestHTTPProtocol string `json:"clientRequestHTTPProtocol"`
		ClientSSLProtocol         string `json:"clientSSLProtocol"`
	} `json:"dimensions"`
}

func (c *GraphQLClient) FetchHTTPRequestsAdaptive(zoneID string, since, until time.Time) ([]HTTPRequestAdaptiveGroup, error) {
	q := `query ($zoneID: String!, $since: Time!, $until: Time!) {
		viewer {
			zones(filter: {zoneTag: $zoneID}) {
				httpRequestsAdaptiveGroups(
					filter: {datetime_geq: $since, datetime_lt: $until}
					limit: 5000
					orderBy: [count_DESC]
				) {
					count
					dimensions {
						cacheStatus
						clientRequestHTTPProtocol
						clientSSLProtocol
					}
				}
			}
		}
	}`

	vars := map[string]interface{}{
		"zoneID": zoneID,
		"since":  since.Format(time.RFC3339),
		"until":  until.Format(time.RFC3339),
	}

	data, err := c.query(q, vars)
	if err != nil {
		return nil, err
	}

	var result HTTPRequestsAdaptiveResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("unmarshal http requests adaptive: %w", err)
	}

	if len(result.Viewer.Zones) == 0 {
		return nil, nil
	}
	return result.Viewer.Zones[0].Groups, nil
}

// --- httpRequestsAdaptiveGroups: security, device, browser, OS, origin status ---

type HTTPSecurityAdaptiveResult struct {
	Viewer struct {
		Zones []struct {
			Groups []HTTPSecurityAdaptiveGroup `json:"httpRequestsAdaptiveGroups"`
		} `json:"zones"`
	} `json:"viewer"`
}

type HTTPSecurityAdaptiveGroup struct {
	Count int `json:"count"`
	Sum   struct {
		EdgeResponseBytes int64 `json:"edgeResponseBytes"`
		EdgeRequestBytes  int64 `json:"edgeRequestBytes"`
	} `json:"sum"`
	Dimensions struct {
		SecurityAction       string `json:"securityAction"`
		SecuritySource       string `json:"securitySource"`
		ClientDeviceType     string `json:"clientDeviceType"`
		UserAgentBrowser     string `json:"userAgentBrowser"`
		UserAgentOS          string `json:"userAgentOS"`
		OriginResponseStatus int    `json:"originResponseStatus"`
	} `json:"dimensions"`
}

func (c *GraphQLClient) FetchHTTPSecurityAdaptive(zoneID string, since, until time.Time) ([]HTTPSecurityAdaptiveGroup, error) {
	q := `query ($zoneID: String!, $since: Time!, $until: Time!) {
		viewer {
			zones(filter: {zoneTag: $zoneID}) {
				httpRequestsAdaptiveGroups(
					filter: {datetime_geq: $since, datetime_lt: $until}
					limit: 5000
					orderBy: [count_DESC]
				) {
					count
					sum {
						edgeResponseBytes
						edgeRequestBytes
					}
					dimensions {
						securityAction
						securitySource
						clientDeviceType
						userAgentBrowser
						userAgentOS
						originResponseStatus
					}
				}
			}
		}
	}`

	vars := map[string]interface{}{
		"zoneID": zoneID,
		"since":  since.Format(time.RFC3339),
		"until":  until.Format(time.RFC3339),
	}

	data, err := c.query(q, vars)
	if err != nil {
		return nil, err
	}

	var result HTTPSecurityAdaptiveResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("unmarshal http security adaptive: %w", err)
	}

	if len(result.Viewer.Zones) == 0 {
		return nil, nil
	}
	return result.Viewer.Zones[0].Groups, nil
}

// --- dnsAnalyticsAdaptiveGroups: DNS query analytics ---

type DNSAnalyticsResult struct {
	Viewer struct {
		Zones []struct {
			Groups []DNSAnalyticsGroup `json:"dnsAnalyticsAdaptiveGroups"`
		} `json:"zones"`
	} `json:"viewer"`
}

type DNSAnalyticsGroup struct {
	Count      int `json:"count"`
	Dimensions struct {
		QueryName    string `json:"queryName"`
		QueryType    string `json:"queryType"`
		ResponseCode string `json:"responseCode"`
	} `json:"dimensions"`
}

func (c *GraphQLClient) FetchDNSAnalytics(zoneID string, since, until time.Time) ([]DNSAnalyticsGroup, error) {
	q := `query ($zoneID: String!, $since: Time!, $until: Time!) {
		viewer {
			zones(filter: {zoneTag: $zoneID}) {
				dnsAnalyticsAdaptiveGroups(
					filter: {datetime_geq: $since, datetime_lt: $until}
					limit: 5000
					orderBy: [count_DESC]
				) {
					count
					dimensions {
						queryName
						queryType
						responseCode
					}
				}
			}
		}
	}`

	vars := map[string]interface{}{
		"zoneID": zoneID,
		"since":  since.Format(time.RFC3339),
		"until":  until.Format(time.RFC3339),
	}

	data, err := c.query(q, vars)
	if err != nil {
		return nil, err
	}

	var result DNSAnalyticsResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("unmarshal dns analytics: %w", err)
	}

	if len(result.Viewer.Zones) == 0 {
		return nil, nil
	}
	return result.Viewer.Zones[0].Groups, nil
}

// --- firewallEventsAdaptiveGroups: WAF/Firewall (requires Pro+ plan) ---

type FirewallEventsResult struct {
	Viewer struct {
		Zones []struct {
			Groups []FirewallEventGroup `json:"firewallEventsAdaptiveGroups"`
		} `json:"zones"`
	} `json:"viewer"`
}

type FirewallEventGroup struct {
	Count      int `json:"count"`
	Dimensions struct {
		Action            string `json:"action"`
		Source            string `json:"source"`
		ClientCountryName string `json:"clientCountryName"`
	} `json:"dimensions"`
}

func (c *GraphQLClient) FetchFirewallEvents(zoneID string, since, until time.Time) ([]FirewallEventGroup, error) {
	q := `query ($zoneID: String!, $since: Time!, $until: Time!) {
		viewer {
			zones(filter: {zoneTag: $zoneID}) {
				firewallEventsAdaptiveGroups(
					filter: {datetime_geq: $since, datetime_lt: $until}
					limit: 5000
					orderBy: [count_DESC]
				) {
					count
					dimensions {
						action
						source
						clientCountryName
					}
				}
			}
		}
	}`

	vars := map[string]interface{}{
		"zoneID": zoneID,
		"since":  since.Format(time.RFC3339),
		"until":  until.Format(time.RFC3339),
	}

	data, err := c.query(q, vars)
	if err != nil {
		return nil, err
	}

	var result FirewallEventsResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("unmarshal firewall events: %w", err)
	}

	if len(result.Viewer.Zones) == 0 {
		return nil, nil
	}
	return result.Viewer.Zones[0].Groups, nil
}

// --- healthCheckEventsAdaptiveGroups: Health checks (requires Pro+ plan) ---

type HealthCheckResult struct {
	Viewer struct {
		Zones []struct {
			Groups []HealthCheckGroup `json:"healthCheckEventsAdaptiveGroups"`
		} `json:"zones"`
	} `json:"viewer"`
}

type HealthCheckGroup struct {
	Count      int `json:"count"`
	Dimensions struct {
		HealthStatus    string `json:"healthStatus"`
		OriginIP        string `json:"originIP"`
		HealthCheckName string `json:"healthCheckName"`
		Region          string `json:"region"`
	} `json:"dimensions"`
}

func (c *GraphQLClient) FetchHealthChecks(zoneID string, since, until time.Time) ([]HealthCheckGroup, error) {
	q := `query ($zoneID: String!, $since: Time!, $until: Time!) {
		viewer {
			zones(filter: {zoneTag: $zoneID}) {
				healthCheckEventsAdaptiveGroups(
					filter: {datetime_geq: $since, datetime_lt: $until}
					limit: 1000
					orderBy: [count_DESC]
				) {
					count
					dimensions {
						healthStatus
						originIP
						healthCheckName
						region
					}
				}
			}
		}
	}`

	vars := map[string]interface{}{
		"zoneID": zoneID,
		"since":  since.Format(time.RFC3339),
		"until":  until.Format(time.RFC3339),
	}

	data, err := c.query(q, vars)
	if err != nil {
		return nil, err
	}

	var result HealthCheckResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("unmarshal health checks: %w", err)
	}

	if len(result.Viewer.Zones) == 0 {
		return nil, nil
	}
	return result.Viewer.Zones[0].Groups, nil
}
