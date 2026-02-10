package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type CloudflareCollector struct {
	cfg    *Config
	client *GraphQLClient

	// HTTP aggregate metrics (from httpRequests1hGroups)
	requestsTotal      *prometheus.Desc
	requestsCached     *prometheus.Desc
	requestsEncrypted  *prometheus.Desc
	bandwidthTotal     *prometheus.Desc
	bandwidthCached    *prometheus.Desc
	bandwidthEncrypted *prometheus.Desc
	threatsTotal       *prometheus.Desc
	pageviewsTotal     *prometheus.Desc
	uniqueVisitors     *prometheus.Desc

	// HTTP breakdown metrics (from httpRequests1hGroups maps)
	requestsByCountry      *prometheus.Desc
	threatsByCountry       *prometheus.Desc
	bandwidthByCountry     *prometheus.Desc
	requestsByStatus       *prometheus.Desc
	requestsByContentType  *prometheus.Desc
	bandwidthByContentType *prometheus.Desc
	pageviewsByBrowser     *prometheus.Desc

	// HTTP per-request dimensions (from httpRequestsAdaptiveGroups)
	requestsByCacheStatus  *prometheus.Desc
	requestsByHTTPProtocol *prometheus.Desc
	requestsBySSLProtocol  *prometheus.Desc

	// Security & client dimensions (from httpRequestsAdaptiveGroups)
	requestsBySecurityAction *prometheus.Desc
	requestsBySecuritySource *prometheus.Desc
	requestsByDeviceType     *prometheus.Desc
	requestsByBrowser        *prometheus.Desc
	requestsByOS             *prometheus.Desc
	requestsByOriginStatus   *prometheus.Desc
	requestBytesTotal        *prometheus.Desc
	responseBytesTotal       *prometheus.Desc

	// DNS (from dnsAnalyticsAdaptiveGroups)
	dnsQueries *prometheus.Desc

	// Firewall (from firewallEventsAdaptiveGroups, Pro+ only)
	firewallEventsByAction  *prometheus.Desc
	firewallEventsBySource  *prometheus.Desc
	firewallEventsByCountry *prometheus.Desc

	// Health checks (Pro+ only)
	healthCheckEvents *prometheus.Desc

	// Meta
	zoneUp         *prometheus.Desc
	scrapeDuration *prometheus.Desc
}

func NewCloudflareCollector(cfg *Config, client *GraphQLClient) *CloudflareCollector {
	return &CloudflareCollector{
		cfg:    cfg,
		client: client,

		// Aggregate HTTP
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
		threatsTotal: prometheus.NewDesc(
			"cloudflare_zone_threats_total",
			"Total number of threats",
			[]string{"zone"}, nil,
		),
		pageviewsTotal: prometheus.NewDesc(
			"cloudflare_zone_pageviews_total",
			"Total number of page views",
			[]string{"zone"}, nil,
		),
		uniqueVisitors: prometheus.NewDesc(
			"cloudflare_zone_unique_visitors",
			"Number of unique visitors",
			[]string{"zone"}, nil,
		),

		// HTTP breakdowns
		requestsByCountry: prometheus.NewDesc(
			"cloudflare_zone_requests_country",
			"Number of requests by client country",
			[]string{"zone", "country"}, nil,
		),
		threatsByCountry: prometheus.NewDesc(
			"cloudflare_zone_threats_country",
			"Number of threats by client country",
			[]string{"zone", "country"}, nil,
		),
		bandwidthByCountry: prometheus.NewDesc(
			"cloudflare_zone_bandwidth_country_bytes",
			"Bandwidth by client country in bytes",
			[]string{"zone", "country"}, nil,
		),
		requestsByStatus: prometheus.NewDesc(
			"cloudflare_zone_requests_status",
			"Number of requests by HTTP response status code",
			[]string{"zone", "status"}, nil,
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

		// Per-request dimensions
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

		// Security & client
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
		responseBytesTotal: prometheus.NewDesc(
			"cloudflare_zone_response_bytes_total",
			"Total outbound response bytes (edge to client)",
			[]string{"zone"}, nil,
		),

		// DNS
		dnsQueries: prometheus.NewDesc(
			"cloudflare_zone_dns_queries",
			"Number of DNS queries",
			[]string{"zone", "query_name", "query_type", "response_code"}, nil,
		),

		// Firewall (Pro+)
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

		// Health checks (Pro+)
		healthCheckEvents: prometheus.NewDesc(
			"cloudflare_zone_health_check_events",
			"Number of health check events",
			[]string{"zone", "status", "origin_ip", "health_check_name", "region"}, nil,
		),

		// Meta
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

func (c *CloudflareCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.requestsTotal
	ch <- c.requestsCached
	ch <- c.requestsEncrypted
	ch <- c.bandwidthTotal
	ch <- c.bandwidthCached
	ch <- c.bandwidthEncrypted
	ch <- c.threatsTotal
	ch <- c.pageviewsTotal
	ch <- c.uniqueVisitors
	ch <- c.requestsByCountry
	ch <- c.threatsByCountry
	ch <- c.bandwidthByCountry
	ch <- c.requestsByStatus
	ch <- c.requestsByContentType
	ch <- c.bandwidthByContentType
	ch <- c.pageviewsByBrowser
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
	ch <- c.responseBytesTotal
	ch <- c.dnsQueries
	ch <- c.firewallEventsByAction
	ch <- c.firewallEventsBySource
	ch <- c.firewallEventsByCountry
	ch <- c.healthCheckEvents
	ch <- c.zoneUp
	ch <- c.scrapeDuration
}

func (c *CloudflareCollector) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()
	until := time.Now().UTC().Truncate(time.Hour)
	since := until.Add(-time.Duration(c.cfg.ScrapeDelay) * time.Second)

	// Ensure the time window covers at least one full hour for 1h groups
	if c.cfg.ScrapeDelay < 3600 {
		since = until.Add(-time.Hour)
	}

	var wg sync.WaitGroup
	for _, zone := range c.cfg.Zones {
		wg.Add(1)
		go func(zoneID string) {
			defer wg.Done()
			c.collectZone(ch, zoneID, since, until)
		}(zone)
	}
	wg.Wait()

	ch <- prometheus.MustNewConstMetric(c.scrapeDuration, prometheus.GaugeValue, time.Since(start).Seconds())
}

func (c *CloudflareCollector) collectZone(ch chan<- prometheus.Metric, zoneID string, since, until time.Time) {
	var wg sync.WaitGroup

	var http1hGroups []HTTPRequests1hGroup
	var httpAdaptiveGroups []HTTPRequestAdaptiveGroup
	var httpSecurityGroups []HTTPSecurityAdaptiveGroup
	var dnsGroups []DNSAnalyticsGroup
	var fwGroups []FirewallEventGroup
	var hcGroups []HealthCheckGroup
	var http1hErr, httpAdaptiveErr, httpSecurityErr, dnsErr, fwErr, hcErr error

	// Adaptive queries use a shorter time window
	adaptiveSince := until.Add(-time.Duration(c.cfg.ScrapeDelay) * time.Second)
	if adaptiveSince.After(since) {
		adaptiveSince = since
	}

	// Fetch all datasets in parallel
	wg.Add(6)
	go func() {
		defer wg.Done()
		http1hGroups, http1hErr = c.client.FetchHTTPRequests1h(zoneID, since, until)
	}()
	go func() {
		defer wg.Done()
		httpAdaptiveGroups, httpAdaptiveErr = c.client.FetchHTTPRequestsAdaptive(zoneID, adaptiveSince, until)
	}()
	go func() {
		defer wg.Done()
		httpSecurityGroups, httpSecurityErr = c.client.FetchHTTPSecurityAdaptive(zoneID, adaptiveSince, until)
	}()
	go func() {
		defer wg.Done()
		dnsGroups, dnsErr = c.client.FetchDNSAnalytics(zoneID, adaptiveSince, until)
	}()
	go func() {
		defer wg.Done()
		fwGroups, fwErr = c.client.FetchFirewallEvents(zoneID, adaptiveSince, until)
	}()
	go func() {
		defer wg.Done()
		hcGroups, hcErr = c.client.FetchHealthChecks(zoneID, adaptiveSince, until)
	}()
	wg.Wait()

	// Zone is up if at least the primary query succeeded
	if http1hErr != nil {
		ch <- prometheus.MustNewConstMetric(c.zoneUp, prometheus.GaugeValue, 0, zoneID)
		log.Printf("zone %s: primary query failed: %v", zoneID, http1hErr)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.zoneUp, prometheus.GaugeValue, 1, zoneID)

	// Process HTTP 1h aggregates
	c.processHTTP1h(ch, zoneID, http1hGroups)

	// Process HTTP adaptive dimensions (cache, protocol, SSL)
	if httpAdaptiveErr != nil {
		log.Printf("zone %s: http adaptive query failed: %v", zoneID, httpAdaptiveErr)
	} else {
		c.processHTTPAdaptive(ch, zoneID, httpAdaptiveGroups)
	}

	// Process HTTP security & client dimensions
	if httpSecurityErr != nil {
		log.Printf("zone %s: http security query failed: %v", zoneID, httpSecurityErr)
	} else {
		c.processHTTPSecurity(ch, zoneID, httpSecurityGroups)
	}

	// Process DNS
	if dnsErr != nil {
		log.Printf("zone %s: dns query failed: %v", zoneID, dnsErr)
	} else {
		c.processDNS(ch, zoneID, dnsGroups)
	}

	// Process firewall (optional, Pro+ plan)
	if fwErr != nil {
		log.Printf("zone %s: firewall query failed (Pro+ required): %v", zoneID, fwErr)
	} else {
		c.processFirewall(ch, zoneID, fwGroups)
	}

	// Process health checks (optional, Pro+ plan)
	if hcErr != nil {
		log.Printf("zone %s: health check query failed (Pro+ required): %v", zoneID, hcErr)
	} else {
		c.processHealthChecks(ch, zoneID, hcGroups)
	}
}

func (c *CloudflareCollector) processHTTP1h(ch chan<- prometheus.Metric, zoneID string, groups []HTTPRequests1hGroup) {
	var totalRequests, totalCached, totalEncrypted int64
	var totalBytes, totalCachedBytes, totalEncryptedBytes int64
	var totalThreats, totalPageViews, totalUniques int64

	countryReqs := make(map[string]int64)
	countryThreats := make(map[string]int64)
	countryBytes := make(map[string]int64)
	statusReqs := make(map[string]int64)
	contentTypeReqs := make(map[string]int64)
	contentTypeBytes := make(map[string]int64)
	browserViews := make(map[string]int64)

	for _, g := range groups {
		totalRequests += g.Sum.Requests
		totalCached += g.Sum.CachedRequests
		totalEncrypted += g.Sum.EncryptedRequests
		totalBytes += g.Sum.Bytes
		totalCachedBytes += g.Sum.CachedBytes
		totalEncryptedBytes += g.Sum.EncryptedBytes
		totalThreats += g.Sum.Threats
		totalPageViews += g.Sum.PageViews
		totalUniques += g.Uniq.Uniques

		for _, entry := range g.Sum.CountryMap {
			countryReqs[entry.Country] += entry.Requests
			countryThreats[entry.Country] += entry.Threats
			countryBytes[entry.Country] += entry.Bytes
		}
		for _, entry := range g.Sum.ResponseStatusMap {
			key := fmt.Sprintf("%d", entry.Status)
			statusReqs[key] += entry.Requests
		}
		for _, entry := range g.Sum.ContentTypeMap {
			if entry.ContentType != "" {
				contentTypeReqs[entry.ContentType] += entry.Requests
				contentTypeBytes[entry.ContentType] += entry.Bytes
			}
		}
		for _, entry := range g.Sum.BrowserMap {
			if entry.Browser != "" {
				browserViews[entry.Browser] += entry.PageViews
			}
		}
	}

	// Aggregate metrics
	ch <- prometheus.MustNewConstMetric(c.requestsTotal, prometheus.GaugeValue, float64(totalRequests), zoneID)
	ch <- prometheus.MustNewConstMetric(c.requestsCached, prometheus.GaugeValue, float64(totalCached), zoneID)
	ch <- prometheus.MustNewConstMetric(c.requestsEncrypted, prometheus.GaugeValue, float64(totalEncrypted), zoneID)
	ch <- prometheus.MustNewConstMetric(c.bandwidthTotal, prometheus.GaugeValue, float64(totalBytes), zoneID)
	ch <- prometheus.MustNewConstMetric(c.bandwidthCached, prometheus.GaugeValue, float64(totalCachedBytes), zoneID)
	ch <- prometheus.MustNewConstMetric(c.bandwidthEncrypted, prometheus.GaugeValue, float64(totalEncryptedBytes), zoneID)
	ch <- prometheus.MustNewConstMetric(c.threatsTotal, prometheus.GaugeValue, float64(totalThreats), zoneID)
	ch <- prometheus.MustNewConstMetric(c.pageviewsTotal, prometheus.GaugeValue, float64(totalPageViews), zoneID)
	ch <- prometheus.MustNewConstMetric(c.uniqueVisitors, prometheus.GaugeValue, float64(totalUniques), zoneID)

	// Breakdown metrics
	for country, reqs := range countryReqs {
		ch <- prometheus.MustNewConstMetric(c.requestsByCountry, prometheus.GaugeValue, float64(reqs), zoneID, country)
	}
	for country, threats := range countryThreats {
		if threats > 0 {
			ch <- prometheus.MustNewConstMetric(c.threatsByCountry, prometheus.GaugeValue, float64(threats), zoneID, country)
		}
	}
	for country, bytes := range countryBytes {
		ch <- prometheus.MustNewConstMetric(c.bandwidthByCountry, prometheus.GaugeValue, float64(bytes), zoneID, country)
	}
	for status, reqs := range statusReqs {
		ch <- prometheus.MustNewConstMetric(c.requestsByStatus, prometheus.GaugeValue, float64(reqs), zoneID, status)
	}
	for ct, reqs := range contentTypeReqs {
		ch <- prometheus.MustNewConstMetric(c.requestsByContentType, prometheus.GaugeValue, float64(reqs), zoneID, ct)
	}
	for ct, bytes := range contentTypeBytes {
		ch <- prometheus.MustNewConstMetric(c.bandwidthByContentType, prometheus.GaugeValue, float64(bytes), zoneID, ct)
	}
	for browser, views := range browserViews {
		ch <- prometheus.MustNewConstMetric(c.pageviewsByBrowser, prometheus.GaugeValue, float64(views), zoneID, browser)
	}
}

func (c *CloudflareCollector) processHTTPAdaptive(ch chan<- prometheus.Metric, zoneID string, groups []HTTPRequestAdaptiveGroup) {
	cacheMap := make(map[string]float64)
	protocolMap := make(map[string]float64)
	sslMap := make(map[string]float64)

	for _, g := range groups {
		count := float64(g.Count)
		if cs := g.Dimensions.CacheStatus; cs != "" {
			cacheMap[cs] += count
		}
		if p := g.Dimensions.ClientRequestHTTPProtocol; p != "" {
			protocolMap[p] += count
		}
		if s := g.Dimensions.ClientSSLProtocol; s != "" {
			sslMap[s] += count
		}
	}

	for cs, count := range cacheMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByCacheStatus, prometheus.GaugeValue, count, zoneID, cs)
	}
	for p, count := range protocolMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByHTTPProtocol, prometheus.GaugeValue, count, zoneID, p)
	}
	for s, count := range sslMap {
		ch <- prometheus.MustNewConstMetric(c.requestsBySSLProtocol, prometheus.GaugeValue, count, zoneID, s)
	}
}

func (c *CloudflareCollector) processHTTPSecurity(ch chan<- prometheus.Metric, zoneID string, groups []HTTPSecurityAdaptiveGroup) {
	secActionMap := make(map[string]float64)
	secSourceMap := make(map[string]float64)
	deviceMap := make(map[string]float64)
	browserMap := make(map[string]float64)
	osMap := make(map[string]float64)
	originStatusMap := make(map[string]float64)
	var totalRequestBytes, totalResponseBytes float64

	for _, g := range groups {
		count := float64(g.Count)
		totalRequestBytes += float64(g.Sum.EdgeRequestBytes)
		totalResponseBytes += float64(g.Sum.EdgeResponseBytes)

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

	ch <- prometheus.MustNewConstMetric(c.requestBytesTotal, prometheus.GaugeValue, totalRequestBytes, zoneID)
	ch <- prometheus.MustNewConstMetric(c.responseBytesTotal, prometheus.GaugeValue, totalResponseBytes, zoneID)

	for action, count := range secActionMap {
		ch <- prometheus.MustNewConstMetric(c.requestsBySecurityAction, prometheus.GaugeValue, count, zoneID, action)
	}
	for source, count := range secSourceMap {
		ch <- prometheus.MustNewConstMetric(c.requestsBySecuritySource, prometheus.GaugeValue, count, zoneID, source)
	}
	for device, count := range deviceMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByDeviceType, prometheus.GaugeValue, count, zoneID, device)
	}
	for browser, count := range browserMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByBrowser, prometheus.GaugeValue, count, zoneID, browser)
	}
	for os, count := range osMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByOS, prometheus.GaugeValue, count, zoneID, os)
	}
	for status, count := range originStatusMap {
		ch <- prometheus.MustNewConstMetric(c.requestsByOriginStatus, prometheus.GaugeValue, count, zoneID, status)
	}
}

func (c *CloudflareCollector) processDNS(ch chan<- prometheus.Metric, zoneID string, groups []DNSAnalyticsGroup) {
	for _, g := range groups {
		ch <- prometheus.MustNewConstMetric(
			c.dnsQueries, prometheus.GaugeValue, float64(g.Count),
			zoneID, g.Dimensions.QueryName, g.Dimensions.QueryType, g.Dimensions.ResponseCode,
		)
	}
}

func (c *CloudflareCollector) processFirewall(ch chan<- prometheus.Metric, zoneID string, groups []FirewallEventGroup) {
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
		ch <- prometheus.MustNewConstMetric(c.firewallEventsByAction, prometheus.GaugeValue, count, zoneID, action)
	}
	for source, count := range sourceMap {
		ch <- prometheus.MustNewConstMetric(c.firewallEventsBySource, prometheus.GaugeValue, count, zoneID, source)
	}
	for country, count := range countryMap {
		ch <- prometheus.MustNewConstMetric(c.firewallEventsByCountry, prometheus.GaugeValue, count, zoneID, country)
	}
}

func (c *CloudflareCollector) processHealthChecks(ch chan<- prometheus.Metric, zoneID string, groups []HealthCheckGroup) {
	for _, g := range groups {
		ch <- prometheus.MustNewConstMetric(
			c.healthCheckEvents, prometheus.GaugeValue, float64(g.Count),
			zoneID, g.Dimensions.HealthStatus, g.Dimensions.OriginIP,
			g.Dimensions.HealthCheckName, g.Dimensions.Region,
		)
	}
}
