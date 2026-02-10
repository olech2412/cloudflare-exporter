package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// counterKey builds a unique key for counter storage from metric name and label values.
func counterKey(parts ...string) string {
	return strings.Join(parts, "\x00")
}

// zoneState holds accumulated counter values and scrape timestamps per zone.
type zoneState struct {
	mu         sync.Mutex
	lastScrape time.Time // last adaptive query boundary
	lastHour   time.Time // last processed 1h boundary
	counters   map[string]float64
}

func newZoneState() *zoneState {
	return &zoneState{
		counters: make(map[string]float64),
	}
}

func (zs *zoneState) add(key string, delta float64) float64 {
	zs.counters[key] += delta
	return zs.counters[key]
}

// cacheHitStatuses are cacheStatus values that count as "cached".
var cacheHitStatuses = map[string]bool{
	"hit":          true,
	"stale":        true,
	"revalidated":  true,
	"updating":     true,
}

type CloudflareCollector struct {
	cfg    *Config
	client *GraphQLClient

	zones   map[string]*zoneState
	zonesMu sync.Mutex

	// Pro+ feature skip flags (log once, then skip)
	skipFirewall     bool
	skipHealthChecks bool

	// Counter metrics (from adaptive queries - accumulate deltas)
	requestsTotal              *prometheus.Desc
	requestsCached             *prometheus.Desc
	requestsEncrypted          *prometheus.Desc
	requestsByStatus           *prometheus.Desc
	requestsByCountry          *prometheus.Desc
	requestsByCacheStatus      *prometheus.Desc
	requestsByHTTPProtocol     *prometheus.Desc
	requestsBySSLProtocol      *prometheus.Desc
	requestsBySecurityAction   *prometheus.Desc
	requestsBySecuritySource   *prometheus.Desc
	requestsByDeviceType       *prometheus.Desc
	requestsByBrowser          *prometheus.Desc
	requestsByOS               *prometheus.Desc
	requestsByOriginStatus     *prometheus.Desc
	requestBytesTotal          *prometheus.Desc
	bandwidthTotal             *prometheus.Desc
	bandwidthCached            *prometheus.Desc
	bandwidthEncrypted         *prometheus.Desc
	bandwidthByCountry         *prometheus.Desc
	dnsQueries                 *prometheus.Desc
	firewallEventsByAction     *prometheus.Desc
	firewallEventsBySource     *prometheus.Desc
	firewallEventsByCountry    *prometheus.Desc
	healthCheckEvents          *prometheus.Desc

	// Counter metrics (from 1h groups - accumulate per completed hour)
	threatsTotal           *prometheus.Desc
	threatsByCountry       *prometheus.Desc
	pageviewsTotal         *prometheus.Desc
	requestsByContentType  *prometheus.Desc
	bandwidthByContentType *prometheus.Desc
	pageviewsByBrowser     *prometheus.Desc

	// Gauge metrics (point-in-time)
	uniqueVisitors *prometheus.Desc
	zoneUp         *prometheus.Desc
	scrapeDuration *prometheus.Desc
}

func NewCloudflareCollector(cfg *Config, client *GraphQLClient) *CloudflareCollector {
	return &CloudflareCollector{
		cfg:    cfg,
		client: client,
		zones:  make(map[string]*zoneState),

		// Counter metrics - adaptive
		requestsTotal: prometheus.NewDesc(
			"cloudflare_zone_requests_total",
			"Total number of HTTP requests",
			[]string{"zone"}, nil,
		),
		requestsCached: prometheus.NewDesc(
			"cloudflare_zone_requests_cached",
			"Number of cached HTTP requests",
			[]string{"zone"}, nil,
		),
		requestsEncrypted: prometheus.NewDesc(
			"cloudflare_zone_requests_encrypted",
			"Number of SSL/TLS encrypted HTTP requests",
			[]string{"zone"}, nil,
		),
		requestsByStatus: prometheus.NewDesc(
			"cloudflare_zone_requests_status",
			"Number of requests by HTTP response status code",
			[]string{"zone", "status"}, nil,
		),
		requestsByCountry: prometheus.NewDesc(
			"cloudflare_zone_requests_country",
			"Number of requests by client country",
			[]string{"zone", "country"}, nil,
		),
		requestsByCacheStatus: prometheus.NewDesc(
			"cloudflare_zone_requests_cache_status",
			"Number of requests by cache status (hit, miss, dynamic, etc.)",
			[]string{"zone", "cache_status"}, nil,
		),
		requestsByHTTPProtocol: prometheus.NewDesc(
			"cloudflare_zone_requests_http_protocol",
			"Number of requests by HTTP protocol version",
			[]string{"zone", "protocol"}, nil,
		),
		requestsBySSLProtocol: prometheus.NewDesc(
			"cloudflare_zone_requests_ssl_protocol",
			"Number of requests by SSL/TLS protocol version",
			[]string{"zone", "ssl_protocol"}, nil,
		),
		requestsBySecurityAction: prometheus.NewDesc(
			"cloudflare_zone_requests_security_action",
			"Number of requests by security action (block, managed_challenge, etc.)",
			[]string{"zone", "action"}, nil,
		),
		requestsBySecuritySource: prometheus.NewDesc(
			"cloudflare_zone_requests_security_source",
			"Number of requests by security source (botFight, waf, firewall, etc.)",
			[]string{"zone", "source"}, nil,
		),
		requestsByDeviceType: prometheus.NewDesc(
			"cloudflare_zone_requests_device_type",
			"Number of requests by client device type (desktop, mobile, etc.)",
			[]string{"zone", "device_type"}, nil,
		),
		requestsByBrowser: prometheus.NewDesc(
			"cloudflare_zone_requests_browser",
			"Number of requests by browser family",
			[]string{"zone", "browser"}, nil,
		),
		requestsByOS: prometheus.NewDesc(
			"cloudflare_zone_requests_os",
			"Number of requests by client operating system",
			[]string{"zone", "os"}, nil,
		),
		requestsByOriginStatus: prometheus.NewDesc(
			"cloudflare_zone_requests_origin_status",
			"Number of requests by origin server response status code",
			[]string{"zone", "status"}, nil,
		),
		requestBytesTotal: prometheus.NewDesc(
			"cloudflare_zone_request_bytes_total",
			"Total inbound request bytes (client to edge)",
			[]string{"zone"}, nil,
		),
		bandwidthTotal: prometheus.NewDesc(
			"cloudflare_zone_bandwidth_total_bytes",
			"Total bandwidth in bytes",
			[]string{"zone"}, nil,
		),
		bandwidthCached: prometheus.NewDesc(
			"cloudflare_zone_bandwidth_cached_bytes",
			"Cached bandwidth in bytes",
			[]string{"zone"}, nil,
		),
		bandwidthEncrypted: prometheus.NewDesc(
			"cloudflare_zone_bandwidth_encrypted_bytes",
			"SSL/TLS encrypted bandwidth in bytes",
			[]string{"zone"}, nil,
		),
		bandwidthByCountry: prometheus.NewDesc(
			"cloudflare_zone_bandwidth_country_bytes",
			"Bandwidth by client country in bytes",
			[]string{"zone", "country"}, nil,
		),
		dnsQueries: prometheus.NewDesc(
			"cloudflare_zone_dns_queries",
			"Number of DNS queries",
			[]string{"zone", "query_name", "query_type", "response_code"}, nil,
		),
		firewallEventsByAction: prometheus.NewDesc(
			"cloudflare_zone_firewall_events_action",
			"Number of firewall events by action (block, challenge, etc.)",
			[]string{"zone", "action"}, nil,
		),
		firewallEventsBySource: prometheus.NewDesc(
			"cloudflare_zone_firewall_events_source",
			"Number of firewall events by source (waf, firewallRules, rateLimit, etc.)",
			[]string{"zone", "source"}, nil,
		),
		firewallEventsByCountry: prometheus.NewDesc(
			"cloudflare_zone_firewall_events_country",
			"Number of firewall events by client country",
			[]string{"zone", "country"}, nil,
		),
		healthCheckEvents: prometheus.NewDesc(
			"cloudflare_zone_health_check_events",
			"Number of health check events",
			[]string{"zone", "status", "origin_ip", "health_check_name", "region"}, nil,
		),

		// Counter metrics - 1h groups
		threatsTotal: prometheus.NewDesc(
			"cloudflare_zone_threats_total",
			"Total number of threats",
			[]string{"zone"}, nil,
		),
		threatsByCountry: prometheus.NewDesc(
			"cloudflare_zone_threats_country",
			"Number of threats by client country",
			[]string{"zone", "country"}, nil,
		),
		pageviewsTotal: prometheus.NewDesc(
			"cloudflare_zone_pageviews_total",
			"Total number of page views",
			[]string{"zone"}, nil,
		),
		requestsByContentType: prometheus.NewDesc(
			"cloudflare_zone_requests_content_type",
			"Number of requests by response content type",
			[]string{"zone", "content_type"}, nil,
		),
		bandwidthByContentType: prometheus.NewDesc(
			"cloudflare_zone_bandwidth_content_type_bytes",
			"Bandwidth by response content type in bytes",
			[]string{"zone", "content_type"}, nil,
		),
		pageviewsByBrowser: prometheus.NewDesc(
			"cloudflare_zone_pageviews_browser",
			"Page views by browser family",
			[]string{"zone", "browser"}, nil,
		),

		// Gauge metrics
		uniqueVisitors: prometheus.NewDesc(
			"cloudflare_zone_unique_visitors",
			"Number of unique visitors (last completed hour)",
			[]string{"zone"}, nil,
		),
		zoneUp: prometheus.NewDesc(
			"cloudflare_zone_up",
			"Whether the zone scrape was successful (1=up, 0=down)",
			[]string{"zone"}, nil,
		),
		scrapeDuration: prometheus.NewDesc(
			"cloudflare_scrape_duration_seconds",
			"Duration of the last scrape in seconds",
			nil, nil,
		),
	}
}

func (c *CloudflareCollector) getZoneState(zoneID string) *zoneState {
	c.zonesMu.Lock()
	defer c.zonesMu.Unlock()
	zs, ok := c.zones[zoneID]
	if !ok {
		zs = newZoneState()
		c.zones[zoneID] = zs
	}
	return zs
}

func (c *CloudflareCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.requestsTotal
	ch <- c.requestsCached
	ch <- c.requestsEncrypted
	ch <- c.requestsByStatus
	ch <- c.requestsByCountry
	ch <- c.requestsByCacheStatus
	ch <- c.requestsByHTTPProtocol
	ch <- c.requestsBySSLProtocol
	ch <- c.requestsBySecurityAction
	ch <- c.requestsBySecuritySource
	ch <- c.requestsByDeviceType
	ch <- c.requestsByBrowser
	ch <- c.requestsByOS
	ch <- c.requestsByOriginStatus
	ch <- c.requestBytesTotal
	ch <- c.bandwidthTotal
	ch <- c.bandwidthCached
	ch <- c.bandwidthEncrypted
	ch <- c.bandwidthByCountry
	ch <- c.dnsQueries
	ch <- c.firewallEventsByAction
	ch <- c.firewallEventsBySource
	ch <- c.firewallEventsByCountry
	ch <- c.healthCheckEvents
	ch <- c.threatsTotal
	ch <- c.threatsByCountry
	ch <- c.pageviewsTotal
	ch <- c.requestsByContentType
	ch <- c.bandwidthByContentType
	ch <- c.pageviewsByBrowser
	ch <- c.uniqueVisitors
	ch <- c.zoneUp
	ch <- c.scrapeDuration
}

func (c *CloudflareCollector) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()
	now := time.Now().UTC()

	var wg sync.WaitGroup
	for _, zone := range c.cfg.Zones {
		wg.Add(1)
		go func(zoneID string) {
			defer wg.Done()
			c.collectZone(ch, zoneID, now)
		}(zone)
	}
	wg.Wait()

	ch <- prometheus.MustNewConstMetric(c.scrapeDuration, prometheus.GaugeValue, time.Since(start).Seconds())
}

func (c *CloudflareCollector) collectZone(ch chan<- prometheus.Metric, zoneID string, now time.Time) {
	zs := c.getZoneState(zoneID)
	zs.mu.Lock()

	// Determine adaptive time window
	adaptiveSince := zs.lastScrape
	if adaptiveSince.IsZero() {
		adaptiveSince = now.Add(-time.Duration(c.cfg.ScrapeDelay) * time.Second)
	}

	// Determine 1h time window
	currentHour := now.Truncate(time.Hour)
	hourSince := zs.lastHour
	if hourSince.IsZero() {
		hourSince = currentHour.Add(-time.Hour)
	}
	needHourlyFetch := currentHour.After(hourSince)

	zs.mu.Unlock()

	// Fetch all data in parallel (no lock held during HTTP calls)
	var (
		adaptiveGroups []HTTPRequestAdaptiveGroup
		securityGroups []HTTPSecurityAdaptiveGroup
		statusGroups   []HTTPStatusGroup
		countryGroups  []HTTPCountryGroup
		http1hGroups   []HTTPRequests1hGroup
		dnsGroups      []DNSAnalyticsGroup
		fwGroups       []FirewallEventGroup
		hcGroups       []HealthCheckGroup

		adaptiveErr, securityErr, statusErr, countryErr error
		http1hErr, dnsErr, fwErr, hcErr                 error
	)

	var wg sync.WaitGroup
	wg.Add(5) // adaptive, security, status, country, dns are always fetched

	go func() {
		defer wg.Done()
		adaptiveGroups, adaptiveErr = c.client.FetchHTTPRequestsAdaptive(zoneID, adaptiveSince, now)
	}()
	go func() {
		defer wg.Done()
		securityGroups, securityErr = c.client.FetchHTTPSecurityAdaptive(zoneID, adaptiveSince, now)
	}()
	go func() {
		defer wg.Done()
		statusGroups, statusErr = c.client.FetchHTTPRequestsByStatus(zoneID, adaptiveSince, now)
	}()
	go func() {
		defer wg.Done()
		countryGroups, countryErr = c.client.FetchHTTPRequestsByCountry(zoneID, adaptiveSince, now)
	}()
	go func() {
		defer wg.Done()
		dnsGroups, dnsErr = c.client.FetchDNSAnalytics(zoneID, adaptiveSince, now)
	}()

	if needHourlyFetch {
		wg.Add(1)
		go func() {
			defer wg.Done()
			http1hGroups, http1hErr = c.client.FetchHTTPRequests1h(zoneID, hourSince, currentHour)
		}()
	}

	if !c.skipFirewall {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fwGroups, fwErr = c.client.FetchFirewallEvents(zoneID, adaptiveSince, now)
		}()
	}

	if !c.skipHealthChecks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hcGroups, hcErr = c.client.FetchHealthChecks(zoneID, adaptiveSince, now)
		}()
	}

	wg.Wait()

	// Check primary query health
	if adaptiveErr != nil {
		ch <- prometheus.MustNewConstMetric(c.zoneUp, prometheus.GaugeValue, 0, zoneID)
		log.Printf("zone %s: primary adaptive query failed: %v", zoneID, adaptiveErr)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.zoneUp, prometheus.GaugeValue, 1, zoneID)

	// Acquire lock, accumulate deltas, emit metrics
	zs.mu.Lock()
	defer zs.mu.Unlock()

	// --- Adaptive: cache, protocol, SSL + bytes ---
	c.processAdaptiveCounters(ch, zoneID, zs, adaptiveGroups)

	// --- Adaptive: security, device, browser, OS, origin ---
	if securityErr != nil {
		log.Printf("zone %s: security adaptive query failed: %v", zoneID, securityErr)
	} else {
		c.processSecurityCounters(ch, zoneID, zs, securityGroups)
	}

	// --- Adaptive: by status ---
	if statusErr != nil {
		log.Printf("zone %s: status query failed: %v", zoneID, statusErr)
	} else {
		c.processStatusCounters(ch, zoneID, zs, statusGroups)
	}

	// --- Adaptive: by country ---
	if countryErr != nil {
		log.Printf("zone %s: country query failed: %v", zoneID, countryErr)
	} else {
		c.processCountryCounters(ch, zoneID, zs, countryGroups)
	}

	// --- DNS ---
	if dnsErr != nil {
		log.Printf("zone %s: dns query failed: %v", zoneID, dnsErr)
	} else {
		c.processDNSCounters(ch, zoneID, zs, dnsGroups)
	}

	// --- Firewall (Pro+) ---
	if fwErr != nil {
		log.Printf("zone %s: firewall query not available (Pro+ required), disabling", zoneID)
		c.skipFirewall = true
	} else if !c.skipFirewall {
		c.processFirewallCounters(ch, zoneID, zs, fwGroups)
	}

	// --- Health checks (Pro+) ---
	if hcErr != nil {
		log.Printf("zone %s: health check query not available (Pro+ required), disabling", zoneID)
		c.skipHealthChecks = true
	} else if !c.skipHealthChecks {
		c.processHealthCheckCounters(ch, zoneID, zs, hcGroups)
	}

	// --- 1h groups (hourly counters + unique visitors gauge) ---
	if needHourlyFetch {
		if http1hErr != nil {
			log.Printf("zone %s: 1h query failed: %v", zoneID, http1hErr)
		} else {
			c.processHourlyCounters(ch, zoneID, zs, http1hGroups)
			zs.lastHour = currentHour
		}
	} else {
		// Emit current counter values even when no new hourly data
		c.emitHourlyCounters(ch, zoneID, zs)
	}

	zs.lastScrape = now
}

func (c *CloudflareCollector) processAdaptiveCounters(ch chan<- prometheus.Metric, zoneID string, zs *zoneState, groups []HTTPRequestAdaptiveGroup) {
	// Aggregate deltas from this scrape window
	var totalCount, cachedCount, encryptedCount float64
	var totalBW, cachedBW, encryptedBW float64
	var totalRequestBytes float64
	cacheMap := make(map[string]float64)
	protocolMap := make(map[string]float64)
	sslMap := make(map[string]float64)

	for _, g := range groups {
		count := float64(g.Count)
		bw := float64(g.Sum.EdgeResponseBytes)
		reqBytes := float64(g.Sum.EdgeRequestBytes)
		totalCount += count
		totalBW += bw
		totalRequestBytes += reqBytes

		cs := g.Dimensions.CacheStatus
		if cs != "" {
			cacheMap[cs] += count
			if cacheHitStatuses[cs] {
				cachedCount += count
				cachedBW += bw
			}
		}

		p := g.Dimensions.ClientRequestHTTPProtocol
		if p != "" {
			protocolMap[p] += count
		}

		s := g.Dimensions.ClientSSLProtocol
		if s != "" {
			sslMap[s] += count
			if s != "none" {
				encryptedCount += count
				encryptedBW += bw
			}
		}
	}

	// Accumulate and emit scalar counters
	ch <- prometheus.MustNewConstMetric(c.requestsTotal, prometheus.CounterValue,
		zs.add(counterKey("requests_total"), totalCount), zoneID)
	ch <- prometheus.MustNewConstMetric(c.requestsCached, prometheus.CounterValue,
		zs.add(counterKey("requests_cached"), cachedCount), zoneID)
	ch <- prometheus.MustNewConstMetric(c.requestsEncrypted, prometheus.CounterValue,
		zs.add(counterKey("requests_encrypted"), encryptedCount), zoneID)
	ch <- prometheus.MustNewConstMetric(c.bandwidthTotal, prometheus.CounterValue,
		zs.add(counterKey("bandwidth_total"), totalBW), zoneID)
	ch <- prometheus.MustNewConstMetric(c.bandwidthCached, prometheus.CounterValue,
		zs.add(counterKey("bandwidth_cached"), cachedBW), zoneID)
	ch <- prometheus.MustNewConstMetric(c.bandwidthEncrypted, prometheus.CounterValue,
		zs.add(counterKey("bandwidth_encrypted"), encryptedBW), zoneID)
	ch <- prometheus.MustNewConstMetric(c.requestBytesTotal, prometheus.CounterValue,
		zs.add(counterKey("request_bytes"), totalRequestBytes), zoneID)

	// Accumulate and emit labeled counters
	for cs, count := range cacheMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByCacheStatus, prometheus.CounterValue,
			zs.add(counterKey("cache_status", cs), count), zoneID, cs)
	}
	for p, count := range protocolMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByHTTPProtocol, prometheus.CounterValue,
			zs.add(counterKey("http_protocol", p), count), zoneID, p)
	}
	for s, count := range sslMap {
		ch <- prometheus.MustNewConstMetric(c.requestsBySSLProtocol, prometheus.CounterValue,
			zs.add(counterKey("ssl_protocol", s), count), zoneID, s)
	}
}

func (c *CloudflareCollector) processSecurityCounters(ch chan<- prometheus.Metric, zoneID string, zs *zoneState, groups []HTTPSecurityAdaptiveGroup) {
	secActionMap := make(map[string]float64)
	secSourceMap := make(map[string]float64)
	deviceMap := make(map[string]float64)
	browserMap := make(map[string]float64)
	osMap := make(map[string]float64)
	originStatusMap := make(map[string]float64)

	for _, g := range groups {
		count := float64(g.Count)

		if a := g.Dimensions.SecurityAction; a != "" && a != "unknown" {
			secActionMap[a] += count
		}
		if s := g.Dimensions.SecuritySource; s != "" && s != "unknown" {
			secSourceMap[s] += count
		}
		if d := g.Dimensions.ClientDeviceType; d != "" {
			deviceMap[d] += count
		}
		if b := g.Dimensions.UserAgentBrowser; b != "" {
			browserMap[b] += count
		}
		if o := g.Dimensions.UserAgentOS; o != "" {
			osMap[o] += count
		}
		if status := g.Dimensions.OriginResponseStatus; status > 0 {
			key := fmt.Sprintf("%d", status)
			originStatusMap[key] += count
		}
	}

	for action, count := range secActionMap {
		ch <- prometheus.MustNewConstMetric(c.requestsBySecurityAction, prometheus.CounterValue,
			zs.add(counterKey("sec_action", action), count), zoneID, action)
	}
	for source, count := range secSourceMap {
		ch <- prometheus.MustNewConstMetric(c.requestsBySecuritySource, prometheus.CounterValue,
			zs.add(counterKey("sec_source", source), count), zoneID, source)
	}
	for device, count := range deviceMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByDeviceType, prometheus.CounterValue,
			zs.add(counterKey("device_type", device), count), zoneID, device)
	}
	for browser, count := range browserMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByBrowser, prometheus.CounterValue,
			zs.add(counterKey("browser", browser), count), zoneID, browser)
	}
	for os, count := range osMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByOS, prometheus.CounterValue,
			zs.add(counterKey("os", os), count), zoneID, os)
	}
	for status, count := range originStatusMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByOriginStatus, prometheus.CounterValue,
			zs.add(counterKey("origin_status", status), count), zoneID, status)
	}
}

func (c *CloudflareCollector) processStatusCounters(ch chan<- prometheus.Metric, zoneID string, zs *zoneState, groups []HTTPStatusGroup) {
	statusMap := make(map[string]float64)
	for _, g := range groups {
		if g.Dimensions.EdgeResponseStatus > 0 {
			key := fmt.Sprintf("%d", g.Dimensions.EdgeResponseStatus)
			statusMap[key] += float64(g.Count)
		}
	}
	for status, count := range statusMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByStatus, prometheus.CounterValue,
			zs.add(counterKey("status", status), count), zoneID, status)
	}
}

func (c *CloudflareCollector) processCountryCounters(ch chan<- prometheus.Metric, zoneID string, zs *zoneState, groups []HTTPCountryGroup) {
	for _, g := range groups {
		if country := g.Dimensions.ClientCountryName; country != "" {
			count := float64(g.Count)
			bw := float64(g.Sum.EdgeResponseBytes)
			ch <- prometheus.MustNewConstMetric(c.requestsByCountry, prometheus.CounterValue,
				zs.add(counterKey("country", country), count), zoneID, country)
			ch <- prometheus.MustNewConstMetric(c.bandwidthByCountry, prometheus.CounterValue,
				zs.add(counterKey("bw_country", country), bw), zoneID, country)
		}
	}
}

func (c *CloudflareCollector) processDNSCounters(ch chan<- prometheus.Metric, zoneID string, zs *zoneState, groups []DNSAnalyticsGroup) {
	for _, g := range groups {
		key := counterKey("dns", g.Dimensions.QueryName, g.Dimensions.QueryType, g.Dimensions.ResponseCode)
		ch <- prometheus.MustNewConstMetric(c.dnsQueries, prometheus.CounterValue,
			zs.add(key, float64(g.Count)),
			zoneID, g.Dimensions.QueryName, g.Dimensions.QueryType, g.Dimensions.ResponseCode)
	}
}

func (c *CloudflareCollector) processFirewallCounters(ch chan<- prometheus.Metric, zoneID string, zs *zoneState, groups []FirewallEventGroup) {
	actionMap := make(map[string]float64)
	sourceMap := make(map[string]float64)
	countryMap := make(map[string]float64)

	for _, g := range groups {
		count := float64(g.Count)
		if a := g.Dimensions.Action; a != "" {
			actionMap[a] += count
		}
		if s := g.Dimensions.Source; s != "" {
			sourceMap[s] += count
		}
		if cn := g.Dimensions.ClientCountryName; cn != "" {
			countryMap[cn] += count
		}
	}

	for action, count := range actionMap {
		ch <- prometheus.MustNewConstMetric(c.firewallEventsByAction, prometheus.CounterValue,
			zs.add(counterKey("fw_action", action), count), zoneID, action)
	}
	for source, count := range sourceMap {
		ch <- prometheus.MustNewConstMetric(c.firewallEventsBySource, prometheus.CounterValue,
			zs.add(counterKey("fw_source", source), count), zoneID, source)
	}
	for country, count := range countryMap {
		ch <- prometheus.MustNewConstMetric(c.firewallEventsByCountry, prometheus.CounterValue,
			zs.add(counterKey("fw_country", country), count), zoneID, country)
	}
}

func (c *CloudflareCollector) processHealthCheckCounters(ch chan<- prometheus.Metric, zoneID string, zs *zoneState, groups []HealthCheckGroup) {
	for _, g := range groups {
		key := counterKey("hc", g.Dimensions.HealthStatus, g.Dimensions.OriginIP,
			g.Dimensions.HealthCheckName, g.Dimensions.Region)
		ch <- prometheus.MustNewConstMetric(c.healthCheckEvents, prometheus.CounterValue,
			zs.add(key, float64(g.Count)),
			zoneID, g.Dimensions.HealthStatus, g.Dimensions.OriginIP,
			g.Dimensions.HealthCheckName, g.Dimensions.Region)
	}
}

func (c *CloudflareCollector) processHourlyCounters(ch chan<- prometheus.Metric, zoneID string, zs *zoneState, groups []HTTPRequests1hGroup) {
	var threats, pageViews float64
	var lastUniques int64
	threatsByCountry := make(map[string]float64)
	contentTypeReqs := make(map[string]float64)
	contentTypeBytes := make(map[string]float64)
	browserViews := make(map[string]float64)

	for _, g := range groups {
		threats += float64(g.Sum.Threats)
		pageViews += float64(g.Sum.PageViews)
		lastUniques = g.Uniq.Uniques // use latest hour's uniques

		for _, entry := range g.Sum.CountryMap {
			if entry.Threats > 0 {
				threatsByCountry[entry.Country] += float64(entry.Threats)
			}
		}
		for _, entry := range g.Sum.ContentTypeMap {
			if entry.ContentType != "" {
				contentTypeReqs[entry.ContentType] += float64(entry.Requests)
				contentTypeBytes[entry.ContentType] += float64(entry.Bytes)
			}
		}
		for _, entry := range g.Sum.BrowserMap {
			if entry.Browser != "" {
				browserViews[entry.Browser] += float64(entry.PageViews)
			}
		}
	}

	// Accumulate and emit hourly counters
	ch <- prometheus.MustNewConstMetric(c.threatsTotal, prometheus.CounterValue,
		zs.add(counterKey("threats_total"), threats), zoneID)
	ch <- prometheus.MustNewConstMetric(c.pageviewsTotal, prometheus.CounterValue,
		zs.add(counterKey("pageviews_total"), pageViews), zoneID)

	for country, t := range threatsByCountry {
		ch <- prometheus.MustNewConstMetric(c.threatsByCountry, prometheus.CounterValue,
			zs.add(counterKey("threats_country", country), t), zoneID, country)
	}
	for ct, reqs := range contentTypeReqs {
		ch <- prometheus.MustNewConstMetric(c.requestsByContentType, prometheus.CounterValue,
			zs.add(counterKey("ct_reqs", ct), reqs), zoneID, ct)
	}
	for ct, bytes := range contentTypeBytes {
		ch <- prometheus.MustNewConstMetric(c.bandwidthByContentType, prometheus.CounterValue,
			zs.add(counterKey("ct_bw", ct), bytes), zoneID, ct)
	}
	for browser, views := range browserViews {
		ch <- prometheus.MustNewConstMetric(c.pageviewsByBrowser, prometheus.CounterValue,
			zs.add(counterKey("pv_browser", browser), views), zoneID, browser)
	}

	// Unique visitors is a gauge (not cumulative) - store for emission between hourly updates
	zs.counters["last_uniques"] = float64(lastUniques)
	ch <- prometheus.MustNewConstMetric(c.uniqueVisitors, prometheus.GaugeValue, float64(lastUniques), zoneID)
}

// emitHourlyCounters emits current accumulated values for hourly counter metrics
// when no new hourly data is available yet.
func (c *CloudflareCollector) emitHourlyCounters(ch chan<- prometheus.Metric, zoneID string, zs *zoneState) {
	// Emit scalar counters at their current accumulated value
	ch <- prometheus.MustNewConstMetric(c.threatsTotal, prometheus.CounterValue,
		zs.counters[counterKey("threats_total")], zoneID)
	ch <- prometheus.MustNewConstMetric(c.pageviewsTotal, prometheus.CounterValue,
		zs.counters[counterKey("pageviews_total")], zoneID)

	// Emit labeled counters for all known keys
	prefix := "threats_country\x00"
	for key, val := range zs.counters {
		if strings.HasPrefix(key, prefix) {
			country := key[len(prefix):]
			ch <- prometheus.MustNewConstMetric(c.threatsByCountry, prometheus.CounterValue, val, zoneID, country)
		}
	}
	prefix = "ct_reqs\x00"
	for key, val := range zs.counters {
		if strings.HasPrefix(key, prefix) {
			ct := key[len(prefix):]
			ch <- prometheus.MustNewConstMetric(c.requestsByContentType, prometheus.CounterValue, val, zoneID, ct)
		}
	}
	prefix = "ct_bw\x00"
	for key, val := range zs.counters {
		if strings.HasPrefix(key, prefix) {
			ct := key[len(prefix):]
			ch <- prometheus.MustNewConstMetric(c.bandwidthByContentType, prometheus.CounterValue, val, zoneID, ct)
		}
	}
	prefix = "pv_browser\x00"
	for key, val := range zs.counters {
		if strings.HasPrefix(key, prefix) {
			browser := key[len(prefix):]
			ch <- prometheus.MustNewConstMetric(c.pageviewsByBrowser, prometheus.CounterValue, val, zoneID, browser)
		}
	}

	// Unique visitors: emit last known value (gauge)
	if val, ok := zs.counters["last_uniques"]; ok {
		ch <- prometheus.MustNewConstMetric(c.uniqueVisitors, prometheus.GaugeValue, val, zoneID)
	}
}
