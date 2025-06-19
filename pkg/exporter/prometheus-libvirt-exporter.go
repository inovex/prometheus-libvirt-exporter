package exporter

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"time"
	"sync"

	"log/slog"

	"github.com/digitalocean/go-libvirt"
	"github.com/digitalocean/go-libvirt/socket/dialers"
	"github.com/inovex/prometheus-libvirt-exporter/libvirt_schema"
	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "libvirt"

var (
	libvirtUpDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Whether scraping libvirt's metrics was successful.",
		nil,
		nil)

	libvirtDomainTimedOutDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain", "timed_out"),
		"Whether scraping libvirt's domain metrics has timed out.",
		[]string{"domain"},
		nil)

	libvirtDomainNumbers = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "domains"),
		"Number of domains",
		nil,
		nil)

	//domain info
	libvirtDomainState = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_info", "state"),
		"Code of the domain state",
		[]string{"domain", "state_desc"},
		nil)
	libvirtDomainInfoMaxMemDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_info", "maximum_memory_bytes"),
		"Maximum allowed memory of the domain, in bytes.",
		[]string{"domain"},
		nil)
	libvirtDomainInfoMemoryDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_info", "memory_usage_bytes"),
		"Memory usage of the domain, in bytes.",
		[]string{"domain"},
		nil)
	libvirtDomainInfoNrVirtCpuDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_info", "virtual_cpus"),
		"Number of virtual CPUs for the domain.",
		[]string{"domain"},
		nil)
	libvirtDomainInfoCpuTimeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_info", "cpu_time_seconds_total"),
		"Amount of CPU time used by the domain, in seconds.",
		[]string{"domain"},
		nil)

	//domain job info
	libvirtDomainJobTypeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_job_info", "type"),
		"Code of the domain job type",
		[]string{"domain"},
		nil)
	libvirtDomainJobTimeElapsedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_job_info", "time_elapsed_seconds"),
		"Time elapsed since the start of the domain job",
		[]string{"domain"},
		nil)
	libvirtDomainJobTimeRemainingDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_job_info", "time_remaining_seconds"),
		"Time remaining until the end of the domain job",
		[]string{"domain"},
		nil)
	libvirtDomainJobDataTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_job_info", "data_total_bytes"),
		"Data total of the domain job",
		[]string{"domain"},
		nil)
	libvirtDomainJobDataProcessedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_job_info", "data_processed_bytes"),
		"Data processed of the domain job",
		[]string{"domain"},
		nil)
	libvirtDomainJobDataRemainingDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_job_info", "data_remaining_bytes"),
		"Data remaining of the domain job",
		[]string{"domain"},
		nil)
	libvirtDomainJobMemTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_job_info", "memory_total_bytes"),
		"Memory total of the domain job",
		[]string{"domain"},
		nil)
	libvirtDomainJobMemProcessedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_job_info", "memory_processed_bytes"),
		"Memory processed of the domain job",
		[]string{"domain"},
		nil)
	libvirtDomainJobMemRemainingDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_job_info", "memory_remaining_bytes"),
		"Memory remaining of the domain job",
		[]string{"domain"},
		nil)
	libvirtDomainJobFileTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_job_info", "file_total_bytes"),
		"File total of the domain job",
		[]string{"domain"},
		nil)
	libvirtDomainJobFileProcessedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_job_info", "file_processed_bytes"),
		"File processed of the domain job",
		[]string{"domain"},
		nil)
	libvirtDomainJobFileRemainingDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_job_info", "file_remaining_bytes"),
		"File remaining of the domain job",
		[]string{"domain"},
		nil)

	//domain memory stats
	libvirtDomainMemoryStatsCurrentBalloonBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "current_balloon_bytes"),
		"Current balloon value (in bytes).",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsMaximumBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "maximum_bytes"),
		"Maximum memory used by the domain (the maximum amount of memory that can be used by the domain)",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsSwapInBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "swap_in_bytes"),
		"Memory swapped in for this domain(the total amount of data read from swap space)",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsSwapOutBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "swap_out_bytes"),
		"Memory swapped out for this domain (the total amount of memory written out to swap space)",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsMajorFaultTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "major_fault_total"),
		"Page faults occur when a process makes a valid access to virtual memory that is not available. "+
			"When servicing the page fault, if disk IO is required, it is considered a major fault.",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsMinorFaultTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "minor_fault_total"),
		"Page faults occur when a process makes a valid access to virtual memory that is not available. "+
			"When servicing the page not fault, if disk IO is required, it is considered a minor fault.",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsUnusedBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "unused_bytes"),
		"Memory unused by the domain",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsAvailableInBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "available_bytes"),
		"Memory available to the domain",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsUsableBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "usable_bytes"),
		"Memory usable by the domain (corresponds to 'Available' in /proc/meminfo)",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsLastUpdateDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "last_update_timestamp_seconds"),
		"Last time the memory stats were updated for this domain, in seconds since epoch.",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsDiskCachesBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "disk_caches_bytes"),
		"Memory used by disk caches for this domain",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsHugeTLBPageAllocTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "hugetlb_pgalloc_total"),
		"The number of successful huge page allocations from inside the domain via virtio balloon",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsHugeTLBPageFailTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "hugetlb_pgfail_total"),
		"The number of failed huge page allocations from inside the domain via virtio balloon",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatsRssBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "rss_bytes"),
		"Resident Set Size of the process running the domain",
		[]string{"domain"},
		nil)
	libvirtDomainMemoryStatUsedPercentDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_memory_stats", "used_percent"),
		"The amount of memory in percent, that used by domain.",
		[]string{"domain"},
		nil)

	//domain block stats
	libvirtDomainBlockStatsInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_block_stats", "info"),
		"Metadata information on block devices.",
		[]string{"domain", "disk_type", "target_bus", "driver_name", "driver_type", "driver_cache", "driver_discard", "source_file", "source_protocol", "target_device", "serial"},
		nil)
	libvirtDomainBlockStatsRdBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_block_stats", "read_bytes_total"),
		"Number of bytes read from a block device, in bytes.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockStatsRdReqDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_block_stats", "read_requests_total"),
		"Number of read requests from a block device.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockStatsWrBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_block_stats", "write_bytes_total"),
		"Number of bytes written from a block device, in bytes.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockStatsWrReqDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_block_stats", "write_requests_total"),
		"Number of write requests from a block device.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockRdTotalTimeSecondsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_block_stats", "read_time_seconds_total"),
		"Total time spent on reads from a block device, in seconds.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockWrTotalTimesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_block_stats", "write_time_seconds_total"),
		"Total time spent on writes on a block device, in seconds",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockFlushReqDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_block_stats", "flush_requests_total"),
		"Total flush requests from a block device.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockFlushTotalTimeSecondsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_block_stats", "flush_time_seconds_total"),
		"Total time in seconds spent on cache flushing to a block device",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainBlockCapacityBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_block_stats", "capacity_bytes"),
		"Logical size in bytes of the block device	backing image.",
		[]string{"domain", "target_device"},
		nil)

	//domain interface stats
	libvirtDomainInterfaceInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_interface_stats", "info"),
		"Metadata on network interfaces.",
		[]string{"domain", "interface_type", "source_bridge", "target_device", "mac_address", "model_type", "mtu_size"},
		nil)
	libvirtDomainInterfaceRxBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_interface_stats", "receive_bytes_total"),
		"Number of bytes received on a network interface, in bytes.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceRxPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_interface_stats", "receive_packets_total"),
		"Number of packets received on a network interface.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceRxErrsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_interface_stats", "receive_errors_total"),
		"Number of packet receive errors on a network interface.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceRxDropDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_interface_stats", "receive_drops_total"),
		"Number of packet receive drops on a network interface.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceTxBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_interface_stats", "transmit_bytes_total"),
		"Number of bytes transmitted on a network interface, in bytes.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceTxPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_interface_stats", "transmit_packets_total"),
		"Number of packets transmitted on a network interface.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceTxErrsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_interface_stats", "transmit_errors_total"),
		"Number of packet transmit errors on a network interface.",
		[]string{"domain", "target_device"},
		nil)
	libvirtDomainInterfaceTxDropDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_interface_stats", "transmit_drops_total"),
		"Number of packet transmit drops on a network interface.",
		[]string{"domain", "target_device"},
		nil)

	// domain vcpu stats
	libvirtDomainVCPUStatsCurrent = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_vcpu", "current"),
		"Number of current online vCPUs.",
		[]string{"domain"},
		nil)
	libvirtDomainVCPUStatsMaximum = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_vcpu", "maximum"),
		"Number of maximum online vCPUs.",
		[]string{"domain"},
		nil)
	libvirtDomainVCPUStatsState = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_vcpu", "state"),
		"State of the vCPU.",
		[]string{"domain", "vcpu"},
		nil)
	libvirtDomainVCPUStatsTime = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_vcpu", "time_seconds_total"),
		"Time spent by the virtual CPU.",
		[]string{"domain", "vcpu"},
		nil)
	libvirtDomainVCPUStatsWait = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_vcpu", "wait_seconds_total"),
		"Time the vCPU wants to run, but the host scheduler has something else running ahead of it.",
		[]string{"domain", "vcpu"},
		nil)
	libvirtDomainVCPUStatsDelay = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_vcpu", "delay_seconds_total"),
		"Time the vCPU spent waiting in the queue instead of running. Exposed to the VM as steal time.",
		[]string{"domain", "vcpu"},
		nil)

	// storage pool stats
	libvirtStoragePoolState = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "storage_pool", "state"),
		"State of the storage pool.",
		[]string{"storage_pool"},
		nil)
	libvirtStoragePoolCapacity = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "storage_pool", "capacity_bytes"),
		"Size of the storage pool in logical bytes.",
		[]string{"storage_pool"},
		nil)
	libvirtStoragePoolAllocation = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "storage_pool", "allocation_bytes"),
		"Current allocation bytes of the storage pool.",
		[]string{"storage_pool"},
		nil)
	libvirtStoragePoolAvailable = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "storage_pool", "available_bytes"),
		"Remaining free space of the storage pool in bytes.",
		[]string{"storage_pool"},
		nil)
	libvirtPoolTimedOutDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "storage_pool", "timed_out"),
		"Whether scraping libvirt's pool metrics has timed out.",
		[]string{"storage_pool"},
		nil)

	// info metrics
	libvirtDomainInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain", "info"),
		"Metadata labels for the domain.",
		[]string{"domain", "os_type", "os_type_arch", "os_type_machine"},
		nil)

	// info metrics from metadata extracted OpenStack Nova
	libvirtDomainOpenstackInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain", "openstack_info"),
		"OpenStack Metadata labels for the domain.",
		[]string{"domain", "instance_name", "instance_id", "flavor_name", "user_name", "user_id", "project_name", "project_id"},
		nil)

	domainState = map[libvirt_schema.DomainState]string{
		libvirt_schema.DOMAIN_NOSTATE:     "no state",
		libvirt_schema.DOMAIN_RUNNING:     "the domain is running",
		libvirt_schema.DOMAIN_BLOCKED:     "the domain is blocked on resource",
		libvirt_schema.DOMAIN_PAUSED:      "the domain is paused by user",
		libvirt_schema.DOMAIN_SHUTDOWN:    "the domain is being shut down",
		libvirt_schema.DOMAIN_SHUTOFF:     "the domain is shut off",
		libvirt_schema.DOMAIN_CRASHED:     "the domain is crashed",
		libvirt_schema.DOMAIN_PMSUSPENDED: "the domain is suspended by guest power management",
		libvirt_schema.DOMAIN_LAST:        "this enum value will increase over time as new events are added to the libvirt API",
	}

	additionalBlockStatName = regexp.MustCompile(`block\.(\d+)\.(.+)`)
	bdevNameRegex           = regexp.MustCompile(`block\.(\d+)\.name`)
	bdevMetricsRegex        = regexp.MustCompile(`block\.(\d+)\..+`)
	bdevMetricRegexTemplate = `block\.%s\.(.+)`
	intNameRegex            = regexp.MustCompile(`net\.(\d+)\.name`)
	intMetricsRegex         = regexp.MustCompile(`net\.(\d+)\.(rx|tx)\.(\w+)`)
	intMetricRegexTemplate  = `net\.%s\.(.+)`
)

type collectFunc func(ch chan<- prometheus.Metric, l *libvirt.Libvirt, domain domainMeta, promLabels []string, logger *slog.Logger, timeout time.Duration) (err error, hasTimedOut bool)

type domainMeta struct {
	domainName      string
	instanceName    string
	instanceId      string
	flavorName      string
	os_type_arch    string
	os_type_machine string
	os_type         string

	userName string
	userId   string

	projectName string
	projectId   string

	libvirtDomain libvirt.Domain
	libvirtSchema libvirt_schema.Domain
}

// LibvirtExporter implements a Prometheus exporter for libvirt state.
type LibvirtExporter struct {
	uri    string
	driver libvirt.ConnectURI

	logger *slog.Logger

	timeout time.Duration
	maxConcurrentCollects int
}

// DomainStatsRecord is a struct to hold the domain stats record.
type DomainStatsRecord struct {
	DomainStatsRecord []libvirt.DomainStatsRecord
	err               error
}

// NewLibvirtExporter creates a new Prometheus exporter for libvirt.
func NewLibvirtExporter(uri string, driver libvirt.ConnectURI, logger *slog.Logger, timeout time.Duration, maxConcurrentCollects int) (*LibvirtExporter, error) {
	return &LibvirtExporter{
		uri:                 uri,
		driver:              driver,
		logger:              logger,
		timeout:             timeout,
		maxConcurrentCollects: maxConcurrentCollects,
	}, nil
}

// DomainsFromLibvirt retrives all domains from the libvirt socket and enriches them with some meta information.
func DomainsFromLibvirt(l *libvirt.Libvirt, logger *slog.Logger) ([]domainMeta, error) {
	domains, _, err := l.ConnectListAllDomains(1, 0)
	if err != nil {
		logger.Error("failed to load domains", "msg", err)
		return nil, err
	}

	lvDomains := make([]domainMeta, len(domains))
	for idx, domain := range domains {
		xmlDesc, err := l.DomainGetXMLDesc(domain, 0)
		if err != nil {
			logger.Error("failed to DomainGetXMLDesc", "domain", domain.Name, "msg", err)
			continue
		}
		var libvirtSchema libvirt_schema.Domain
		if err = xml.Unmarshal([]byte(xmlDesc), &libvirtSchema); err != nil {
			logger.Error("failed to unmarshal domain", "domain", domain.Name, "msg", err)
			continue
		}

		lvDomains[idx].libvirtDomain = domain
		lvDomains[idx].libvirtSchema = libvirtSchema

		lvDomains[idx].domainName = domain.Name
		lvDomains[idx].instanceName = libvirtSchema.Metadata.NovaInstance.Name
		lvDomains[idx].instanceId = libvirtSchema.UUID
		lvDomains[idx].flavorName = libvirtSchema.Metadata.NovaInstance.Flavor.FlavorName
		lvDomains[idx].os_type_arch = libvirtSchema.OSMetadata.Type.Arch
		lvDomains[idx].os_type_machine = libvirtSchema.OSMetadata.Type.Machine
		lvDomains[idx].os_type = libvirtSchema.OSMetadata.Type.Value

		lvDomains[idx].userName = libvirtSchema.Metadata.NovaInstance.Owner.User.UserName
		lvDomains[idx].userId = libvirtSchema.Metadata.NovaInstance.Owner.User.UserId

		lvDomains[idx].projectName = libvirtSchema.Metadata.NovaInstance.Owner.Project.ProjectName
		lvDomains[idx].projectId = libvirtSchema.Metadata.NovaInstance.Owner.Project.ProjectId
	}

	return lvDomains, nil
}

// Collect scrapes Prometheus metrics from libvirt.
func (e *LibvirtExporter) Collect(ch chan<- prometheus.Metric) {
	if err := CollectFromLibvirt(ch, e.uri, e.driver, e.logger, e.timeout, e.maxConcurrentCollects); err != nil {
		e.logger.Error("failed to collect metrics", "msg", err)
	}
}

// CollectFromLibvirt obtains Prometheus metrics from all domains in a libvirt setup.
func CollectFromLibvirt(ch chan<- prometheus.Metric, uri string, driver libvirt.ConnectURI, logger *slog.Logger, timeout time.Duration, maxConcurrentCollects int) (err error) {
	var (
		wg sync.WaitGroup 
		pools []libvirt.StoragePool
	)
	
	dialer := dialers.NewLocal(dialers.WithSocket(uri), dialers.WithLocalTimeout(5*time.Second))
	l := libvirt.NewWithDialer(dialer)
	if err = l.ConnectToURI(driver); err != nil {
		logger.Error("failed to connect", "msg", err)
		// if we cannot connect to libvirt, we set the up metric to 0
		ch <- prometheus.MustNewConstMetric(
			libvirtUpDesc,
			prometheus.GaugeValue,
			0.0)
		return err
	}

	defer func() {
		if err := l.Disconnect(); err != nil {
			logger.Error("failed to disconnect", "msg", err)
		}
	}()

	// if we can connect to libvirt, we set the up metric to 1
	ch <- prometheus.MustNewConstMetric(
		libvirtUpDesc,
		prometheus.GaugeValue,
		1.0)

	// get all domains
	// see https://libvirt.org/html/libvirt-libvirt-domain.html
	domains, err := DomainsFromLibvirt(l, logger)
	if err != nil {
		logger.Error("failed to retrieve domains from Libvirt", "msg", err)
		return err
	}

	// set the number of domains metric
	domainNumber := len(domains)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainNumbers,
		prometheus.GaugeValue,
		float64(domainNumber))

	// get all storage pools
	// see https://libvirt.org/html/libvirt-libvirt-storage.html
	if pools, _, err = l.ConnectListAllStoragePools(1, 0); err != nil {
		logger.Error("failed to collect storage pools", "msg", err)
		return err
	}

	// create a buffered channel for domains and pools
	domainChan := make(chan domainMeta, len(domains))
	poolChan := make(chan libvirt.StoragePool, len(pools))

	for _, domain := range domains {
		domainChan <- domain
	}

	for _, pool := range pools {
		poolChan <- pool
	}

	// worker function to process domains and pools concurrently
	worker := func() {
		defer wg.Done()
		for {
			select {
			case domain := <-domainChan:
				if err, hasTimedOut := CollectDomain(ch, l, domain, logger, timeout); err != nil {
					logger.Error("failed to collect domain", "domain", domain.domainName, "msg", err)
					if hasTimedOut {
						ch <- prometheus.MustNewConstMetric(libvirtDomainTimedOutDesc, prometheus.GaugeValue, float64(1), domain.domainName)
						logger.Error("call to CollectDomain has timed out", "domain", domain.domainName)
					}
				} else {
					ch <- prometheus.MustNewConstMetric(libvirtDomainTimedOutDesc, prometheus.GaugeValue, float64(0), domain.domainName)
				}
			case pool := <-poolChan:
				if err, hasTimedOut := CollectStoragePoolInfo(ch, l, pool, logger, timeout); err != nil {
					logger.Error("failed to collect storage pool", "pool", pool.Name, "msg", err)
					if hasTimedOut {
						logger.Error("call to CollectStoragePool has timed out", "pool", pool.Name)
						ch <- prometheus.MustNewConstMetric(libvirtPoolTimedOutDesc, prometheus.GaugeValue, float64(1), pool.Name)
					}
				} else {
					ch <- prometheus.MustNewConstMetric(libvirtPoolTimedOutDesc, prometheus.GaugeValue, float64(0), pool.Name)
				}
			default:
				return // no more domains or pool to process
			}
		}
	}

	// start workers to process domains and pools concurrently
	wg.Add(maxConcurrentCollects)
	for i := 0; i < maxConcurrentCollects; i++ {
		go worker()
	}

	// wait for all workers to finish
	wg.Wait()

	return nil
}

// CollectDomain extracts Prometheus metrics from a libvirt domain.
func CollectDomain(ch chan<- prometheus.Metric, l *libvirt.Libvirt, domain domainMeta, logger *slog.Logger, timeout time.Duration) (err error, hasTimedOut bool) {
	var (
		rState                     uint8
		rvirCpu                    uint16
		rmaxmem, rmemory, rcputime uint64
	)
	type rDomainStatsState struct {
		rState                     uint8
		rvirCpu                    uint16
		rmaxmem, rmemory, rcputime uint64
		err                        error
	}

	chDomainStats := make(chan rDomainStatsState, 1)
	go func() {
		var data rDomainStatsState
		data.rState, data.rmaxmem, data.rmemory, data.rvirCpu, data.rcputime, data.err = l.DomainGetInfo(domain.libvirtDomain)
		chDomainStats <- data
	}()

	select {
	case res := <-chDomainStats:
		if res.err != nil {
			return res.err, false
		}

		rState = res.rState
		rvirCpu = res.rvirCpu
		rmaxmem = res.rmaxmem
		rmemory = res.rmemory
		rcputime = res.rcputime
	case <-time.After(time.Duration(timeout) * time.Second):
		return fmt.Errorf("call to DomainGetInfo has timed out"), true
	}

	openstackInfoLabels := []string{
		domain.domainName,
		domain.instanceName,
		domain.instanceId,
		domain.flavorName,
		domain.userName,
		domain.userId,
		domain.projectName,
		domain.projectId,
	}

	infoLabels := []string{
		domain.domainName,
		domain.os_type,
		domain.os_type_arch,
		domain.os_type_machine,
	}

	promLabels := []string{
		domain.domainName,
	}

	ch <- prometheus.MustNewConstMetric(libvirtDomainInfoDesc, prometheus.GaugeValue, 1.0, infoLabels...)
	ch <- prometheus.MustNewConstMetric(libvirtDomainOpenstackInfoDesc, prometheus.GaugeValue, 1.0, openstackInfoLabels...)

	ch <- prometheus.MustNewConstMetric(libvirtDomainState, prometheus.GaugeValue, float64(rState), append(promLabels, domainState[libvirt_schema.DomainState(rState)])...)

	ch <- prometheus.MustNewConstMetric(libvirtDomainInfoMaxMemDesc, prometheus.GaugeValue, float64(rmaxmem)*1024, promLabels...)
	ch <- prometheus.MustNewConstMetric(libvirtDomainInfoMemoryDesc, prometheus.GaugeValue, float64(rmemory)*1024, promLabels...)
	ch <- prometheus.MustNewConstMetric(libvirtDomainInfoNrVirtCpuDesc, prometheus.GaugeValue, float64(rvirCpu), promLabels...)
	ch <- prometheus.MustNewConstMetric(libvirtDomainInfoCpuTimeDesc, prometheus.CounterValue, float64(rcputime)/1e9, promLabels...)

	var isActive int32
	if isActive, err = l.DomainIsActive(domain.libvirtDomain); err != nil {
		logger.Error("failed to get active status of domain", "domain", domain.libvirtDomain.Name, "msg", err)
		return err, false
	}
	if isActive != 1 {
		logger.Debug("domain is not active, skipping", "domain", domain.libvirtDomain.Name)
		return nil, false
	}

	for _, collectFunc := range []collectFunc{CollectDomainBlockDeviceInfo, CollectDomainNetworkInfo, CollectDomainJobInfo, CollectDomainMemoryStatInfo, CollectDomainVCPUInfo} {
		if err, hasTimedOut = collectFunc(ch, l, domain, promLabels, logger, timeout); err != nil {
			logger.Error("failed to collect some domain info", "domain", domain.libvirtDomain.Name, "msg", err)
			return err, hasTimedOut
		}
	}

	return nil, false
}

func GenerateAdditionalBlockMetrics(ch chan<- prometheus.Metric, prometheusDiskLabels []string, capacity uint64, flushRequests uint64, flushTimes uint64, readTime uint64, writeTime uint64) {
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainBlockRdTotalTimeSecondsDesc,
		prometheus.CounterValue,
		float64(readTime)/1e9,
		prometheusDiskLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainBlockWrTotalTimesDesc,
		prometheus.CounterValue,
		float64(writeTime)/1e9,
		prometheusDiskLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainBlockFlushReqDesc,
		prometheus.CounterValue,
		float64(flushRequests),
		prometheusDiskLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainBlockFlushTotalTimeSecondsDesc,
		prometheus.CounterValue,
		float64(flushTimes)/1e9,
		prometheusDiskLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainBlockCapacityBytesDesc,
		prometheus.GaugeValue,
		float64(capacity),
		prometheusDiskLabels...)
}

func connectGetAllDomainStats(l *libvirt.Libvirt, domain domainMeta, flag libvirt.DomainStatsTypes, chRes chan<- DomainStatsRecord) {
	var data DomainStatsRecord

	data.DomainStatsRecord, data.err = l.ConnectGetAllDomainStats([]libvirt.Domain{domain.libvirtDomain}, uint32(flag), uint32(libvirt.ConnectGetAllDomainsStatsNowait))
	chRes <- data
}

func CollectAdditionalDomainBlockDeviceInfo(ch chan<- prometheus.Metric, l *libvirt.Libvirt, domain domainMeta, promLabels []string, logger *slog.Logger, timeout time.Duration) (err error, hasTimedOut bool) {
	var data []libvirt.DomainStatsRecord

	chRes := make(chan DomainStatsRecord, 1)
	go connectGetAllDomainStats(l, domain, libvirt.DomainStatsBlock, chRes)

	select {
	case res := <-chRes:
		if res.err != nil {
			return res.err, false
		}
		data = res.DomainStatsRecord
	case <-time.After(time.Duration(timeout) * time.Second):
		return fmt.Errorf("call to ConnectGetAllDomainStats with DomainStatsBlock flag has timed out"), true
	}

	domainBlockStats := data[0]
	statsIndex := "no_stats"
	var capacity, flushRequests, flushTimes, readTime, writeTime uint64
	var prometheusDiskLabels []string
	for _, param := range domainBlockStats.Params {
		if matches := additionalBlockStatName.FindStringSubmatch(param.Field); matches != nil {
			if statsIndex != "no_stats" && statsIndex != matches[1] {
				GenerateAdditionalBlockMetrics(ch, prometheusDiskLabels, capacity, flushRequests, flushTimes, readTime, writeTime)
			}
			statsIndex = matches[1]
			switch matches[2] {
			case "name":
				prometheusDiskLabels = append(promLabels, param.Value.I.(string))
			case "rd.times":
				readTime = param.Value.I.(uint64)
			case "wr.times":
				writeTime = param.Value.I.(uint64)
			case "fl.reqs":
				flushRequests = param.Value.I.(uint64)
			case "fl.times":
				flushTimes = param.Value.I.(uint64)
			case "capacity":
				capacity = param.Value.I.(uint64)
			}
		}
	}
	if statsIndex != "no_stats" {
		GenerateAdditionalBlockMetrics(ch, prometheusDiskLabels, capacity, flushRequests, flushTimes, readTime, writeTime)
	}

	return
}

func CollectDomainBlockDeviceInfo(ch chan<- prometheus.Metric, l *libvirt.Libvirt, domain domainMeta, promLabels []string, logger *slog.Logger, timeout time.Duration) (err error, hasTimedOut bool) {
	var data []libvirt.DomainStatsRecord

	chRes := make(chan DomainStatsRecord, 1)

	go connectGetAllDomainStats(l, domain, libvirt.DomainStatsBlock, chRes)

	select {
	case res := <-chRes:
		if res.err != nil {
			return res.err, false
		}
		data = res.DomainStatsRecord
	case <-time.After(time.Duration(timeout) * time.Second):
		return fmt.Errorf("call to ConnectGetAllDomainStats with DomainStatsBlock flag has timed out"), true
	}

	if len(data) == 0 {
		return fmt.Errorf("no block stats available"), false
	}

	domainStatBlock := data[0]
	for _, disk := range domain.libvirtSchema.Devices.Disks {
		if disk.Device == "cdrom" || disk.Device == "fd" {
			continue
		}
		var rRdReq, rRdBytes, rWrReq, rWrBytes uint64

		bdev_name := bdevNameRegex
		bdev_metrics := bdevMetricsRegex
		var bdevIdx string
		for _, param := range domainStatBlock.Params {
			switch {
			case bdev_name.MatchString(param.Field):
				// We have a match for the block device name
				match := bdev_name.FindStringSubmatch(param.Field)

				if param.Value.I.(string) == disk.Target.Device {
					bdevIdx = match[1]
				}
			case len(bdevIdx) > 0 && bdev_metrics.FindStringSubmatch(param.Field)[1] == bdevIdx:
				// We have a match for the block device index
				bdev_metric := regexp.MustCompile(fmt.Sprintf(bdevMetricRegexTemplate, bdevIdx))
				metric := bdev_metric.FindStringSubmatch(param.Field)
				switch metric[1] {
				case "rd.bytes":
					rRdBytes = param.Value.I.(uint64)
				case "rd.reqs":
					rRdReq = param.Value.I.(uint64)
				case "wr.bytes":
					rWrBytes = param.Value.I.(uint64)
				case "wr.reqs":
					rWrReq = param.Value.I.(uint64)
				}
			}
		}

		promDiskLabels := append(promLabels, disk.Target.Device)
		ch <- prometheus.MustNewConstMetric(
			libvirtDomainBlockStatsRdBytesDesc,
			prometheus.CounterValue,
			float64(rRdBytes),
			promDiskLabels...)
		ch <- prometheus.MustNewConstMetric(
			libvirtDomainBlockStatsRdReqDesc,
			prometheus.CounterValue,
			float64(rRdReq),
			promDiskLabels...)
		ch <- prometheus.MustNewConstMetric(
			libvirtDomainBlockStatsWrBytesDesc,
			prometheus.CounterValue,
			float64(rWrBytes),
			promDiskLabels...)
		ch <- prometheus.MustNewConstMetric(
			libvirtDomainBlockStatsWrReqDesc,
			prometheus.CounterValue,
			float64(rWrReq),
			promDiskLabels...)
		promDiskInfoLabels := append(promLabels, disk.Type, disk.Target.Bus, disk.Driver.Name, disk.Driver.Type, disk.Driver.Cache, disk.Driver.Discard, disk.Source.File, disk.Source.Protocol, disk.Target.Device, disk.Serial)
		ch <- prometheus.MustNewConstMetric(
			libvirtDomainBlockStatsInfo,
			prometheus.GaugeValue,
			float64(1),
			promDiskInfoLabels...)
	}

	if err, hasTimedOut := CollectAdditionalDomainBlockDeviceInfo(ch, l, domain, promLabels, logger, timeout); err != nil {
		return err, hasTimedOut
	}

	return
}

func CollectDomainNetworkInfo(ch chan<- prometheus.Metric, l *libvirt.Libvirt, domain domainMeta, promLabels []string, logger *slog.Logger, timeout time.Duration) (err error, hasTimedOut bool) {
	var data []libvirt.DomainStatsRecord

	chRes := make(chan DomainStatsRecord, 1)

	go connectGetAllDomainStats(l, domain, libvirt.DomainStatsInterface, chRes)

	select {
	case res := <-chRes:
		if res.err != nil {
			return res.err, false
		}
		data = res.DomainStatsRecord
	case <-time.After(time.Duration(timeout) * time.Second):
		return fmt.Errorf("call to ConnectGetAllDomainStats with DomainStatsInterface flag has timed out"), true
	}

	domainStatsInterface := data[0]
	for _, iface := range domain.libvirtSchema.Devices.Interfaces {
		if iface.Target.Device == "" {
			continue
		}
		var rRxBytes, rRxPackets, rRxErrs, rRxDrop, rTxBytes, rTxPackets, rTxErrs, rTxDrop uint64

		int_name := intNameRegex
		int_metrics := intMetricsRegex
		var intIdx string
		for _, param := range domainStatsInterface.Params {
			switch {
			case int_name.MatchString(param.Field):
				// We have a match for the interface name
				match := int_name.FindStringSubmatch(param.Field)

				if param.Value.I.(string) == iface.Target.Device {
					intIdx = match[1]
				}
			case len(intIdx) > 0 && int_metrics.FindStringSubmatch(param.Field)[1] == intIdx:
				// We have a match for the interface index
				int_metric := regexp.MustCompile(fmt.Sprintf(intMetricRegexTemplate, intIdx))
				metric := int_metric.FindStringSubmatch(param.Field)
				switch metric[1] {
				case "rx.bytes":
					rRxBytes = param.Value.I.(uint64)
				case "rx.pkts":
					rRxPackets = param.Value.I.(uint64)
				case "rx.errs":
					rRxErrs = param.Value.I.(uint64)
				case "rx.drop":
					rRxDrop = param.Value.I.(uint64)
				case "tx.bytes":
					rTxBytes = param.Value.I.(uint64)
				case "tx.pkts":
					rTxPackets = param.Value.I.(uint64)
				case "tx.errs":
					rTxErrs = param.Value.I.(uint64)
				case "tx.drop":
					rTxDrop = param.Value.I.(uint64)
				}
			}
		}

		promInterfaceLabels := append(promLabels, iface.Target.Device)
		ch <- prometheus.MustNewConstMetric(
			libvirtDomainInterfaceRxBytesDesc,
			prometheus.CounterValue,
			float64(rRxBytes),
			promInterfaceLabels...)

		ch <- prometheus.MustNewConstMetric(
			libvirtDomainInterfaceRxPacketsDesc,
			prometheus.CounterValue,
			float64(rRxPackets),
			promInterfaceLabels...)

		ch <- prometheus.MustNewConstMetric(
			libvirtDomainInterfaceRxErrsDesc,
			prometheus.CounterValue,
			float64(rRxErrs),
			promInterfaceLabels...)

		ch <- prometheus.MustNewConstMetric(
			libvirtDomainInterfaceRxDropDesc,
			prometheus.CounterValue,
			float64(rRxDrop),
			promInterfaceLabels...)

		ch <- prometheus.MustNewConstMetric(
			libvirtDomainInterfaceTxBytesDesc,
			prometheus.CounterValue,
			float64(rTxBytes),
			promInterfaceLabels...)

		ch <- prometheus.MustNewConstMetric(
			libvirtDomainInterfaceTxPacketsDesc,
			prometheus.CounterValue,
			float64(rTxPackets),
			promInterfaceLabels...)

		ch <- prometheus.MustNewConstMetric(
			libvirtDomainInterfaceTxErrsDesc,
			prometheus.CounterValue,
			float64(rTxErrs),
			promInterfaceLabels...)

		ch <- prometheus.MustNewConstMetric(
			libvirtDomainInterfaceTxDropDesc,
			prometheus.CounterValue,
			float64(rTxDrop),
			promInterfaceLabels...)

		promInterfaceInfoLabels := append(promLabels, iface.Type, iface.Source.Bridge, iface.Target.Device, iface.MAC.Address, iface.Model.Type, iface.MTU.Size)
		ch <- prometheus.MustNewConstMetric(
			libvirtDomainInterfaceInfo,
			prometheus.GaugeValue,
			float64(1),
			promInterfaceInfoLabels...)
	}

	return
}

func CollectDomainJobInfo(ch chan<- prometheus.Metric, l *libvirt.Libvirt, domain domainMeta, promLabels []string, logger *slog.Logger, timeout time.Duration) (err error, hasTimedOut bool) {
	var (
		rType int32
		rTimeElapsed, rTimeRemaining, rDataTotal, rDataProcessed, rDataRemaining, rMemTotal,
		rMemProcessed, rMemRemaining, rFileTotal, rFileProcessed, rFileRemaining uint64
	)

	type rDomainGetJobInfo struct {
		rType int32
		rTimeElapsed, rTimeRemaining, rDataTotal, rDataProcessed, rDataRemaining, rMemTotal,
		rMemProcessed, rMemRemaining, rFileTotal, rFileProcessed, rFileRemaining uint64
		err error
	}

	chDomainGetJobInfo := make(chan rDomainGetJobInfo, 1)
	go func() {
		var data rDomainGetJobInfo
		data.rType, data.rTimeElapsed, data.rTimeRemaining, data.rDataTotal, data.rDataProcessed, data.rDataRemaining,
			data.rMemTotal, data.rMemProcessed, data.rMemRemaining, data.rFileTotal, data.rFileProcessed, data.rFileRemaining, data.err = l.DomainGetJobInfo(domain.libvirtDomain)
		chDomainGetJobInfo <- data
	}()

	select {
	case res := <-chDomainGetJobInfo:

		if res.err != nil {
			libvirtErr, _ := res.err.(libvirt.Error)
			if libvirtErr.Code == 84 { // VIR_ERR_OPERATION_UNSUPPORTED (https://github.com/inovex/prometheus-libvirt-exporter/pull/77#issuecomment-2826913542)
				return nil, false
			}
			return res.err, false
		}
		rType = res.rType
		rTimeElapsed = res.rTimeElapsed
		rTimeRemaining = res.rTimeRemaining
		rDataTotal = res.rDataTotal
		rDataProcessed = res.rDataProcessed
		rDataRemaining = res.rDataRemaining
		rMemTotal = res.rMemTotal
		rMemProcessed = res.rMemProcessed
		rMemRemaining = res.rMemRemaining
		rFileTotal = res.rFileTotal
		rFileProcessed = res.rFileProcessed
		rFileRemaining = res.rFileRemaining
	case <-time.After(time.Duration(timeout) * time.Second):
		return fmt.Errorf("call to DomainGetJobInfo has timed out"), true
	}

	ch <- prometheus.MustNewConstMetric(
		libvirtDomainJobTypeDesc,
		prometheus.GaugeValue,
		float64(rType),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainJobTimeElapsedDesc,
		prometheus.GaugeValue,
		float64(rTimeElapsed),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainJobTimeRemainingDesc,
		prometheus.GaugeValue,
		float64(rTimeRemaining),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainJobDataTotalDesc,
		prometheus.GaugeValue,
		float64(rDataTotal),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainJobDataProcessedDesc,
		prometheus.GaugeValue,
		float64(rDataProcessed),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainJobDataRemainingDesc,
		prometheus.GaugeValue,
		float64(rDataRemaining),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainJobMemTotalDesc,
		prometheus.GaugeValue,
		float64(rMemTotal),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainJobMemProcessedDesc,
		prometheus.GaugeValue,
		float64(rMemProcessed),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainJobMemRemainingDesc,
		prometheus.GaugeValue,
		float64(rMemRemaining),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainJobFileTotalDesc,
		prometheus.GaugeValue,
		float64(rFileTotal),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainJobFileProcessedDesc,
		prometheus.GaugeValue,
		float64(rFileProcessed),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainJobFileRemainingDesc,
		prometheus.GaugeValue,
		float64(rFileRemaining),
		promLabels...)

	return
}

func CollectDomainMemoryStatInfo(ch chan<- prometheus.Metric, l *libvirt.Libvirt, domain domainMeta, promLabels []string, logger *slog.Logger, timeout time.Duration) (err error, hasTimedOut bool) {
	var data []libvirt.DomainStatsRecord

	chRes := make(chan DomainStatsRecord)

	go connectGetAllDomainStats(l, domain, libvirt.DomainStatsBalloon, chRes)

	select {
	case res := <-chRes:
		if res.err != nil {
			return res.err, false
		}
		data = res.DomainStatsRecord
	case <-time.After(time.Duration(timeout) * time.Second):
		return fmt.Errorf("call to ConnectGetAllDomainStats with DomainStatsBalloon flag has timed out"), true
	}

	domainStatsMemory := data[0]
	var available, usable uint64
	for _, param := range domainStatsMemory.Params {
		switch param.Field {
		case "balloon.current":
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsCurrentBalloonBytesDesc,
				prometheus.GaugeValue,
				float64(param.Value.I.(uint64)*1024),
				promLabels...)
		case "balloon.maximum":
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsMaximumBytesDesc,
				prometheus.GaugeValue,
				float64(param.Value.I.(uint64)*1024),
				promLabels...)
		case "balloon.swap_in":
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsSwapInBytesDesc,
				prometheus.GaugeValue,
				float64(param.Value.I.(uint64)*1024),
				promLabels...)
		case "balloon.swap_out":
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsSwapOutBytesDesc,
				prometheus.GaugeValue,
				float64(param.Value.I.(uint64)*1024),
				promLabels...)
		case "balloon.major_fault":
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsMajorFaultTotalDesc,
				prometheus.CounterValue,
				float64(param.Value.I.(uint64)),
				promLabels...)
		case "balloon.minor_fault":
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsMinorFaultTotalDesc,
				prometheus.CounterValue,
				float64(param.Value.I.(uint64)),
				promLabels...)
		case "balloon.unused":
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsUnusedBytesDesc,
				prometheus.GaugeValue,
				float64(param.Value.I.(uint64)*1024),
				promLabels...)
		case "balloon.available":
			available = param.Value.I.(uint64)
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsAvailableInBytesDesc,
				prometheus.GaugeValue,
				float64(param.Value.I.(uint64)*1024),
				promLabels...)
		case "balloon.usable":
			usable = param.Value.I.(uint64)
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsUsableBytesDesc,
				prometheus.GaugeValue,
				float64(param.Value.I.(uint64)*1024),
				promLabels...)
		case "balloon.last-update":
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsLastUpdateDesc,
				prometheus.GaugeValue,
				float64(param.Value.I.(uint64)),
				promLabels...)
		case "balloon.disk_caches":
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsDiskCachesBytesDesc,
				prometheus.GaugeValue,
				float64(param.Value.I.(uint64)*1024),
				promLabels...)
		case "balloon.hugetlb_pgalloc":
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsHugeTLBPageAllocTotalDesc,
				prometheus.GaugeValue,
				float64(param.Value.I.(uint64)),
				promLabels...)
		case "balloon.hugetlb_pgfail":
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsHugeTLBPageFailTotalDesc,
				prometheus.GaugeValue,
				float64(param.Value.I.(uint64)),
				promLabels...)
		case "balloon.rss":
			ch <- prometheus.MustNewConstMetric(
				libvirtDomainMemoryStatsRssBytesDesc,
				prometheus.GaugeValue,
				float64(param.Value.I.(uint64)*1024),
				promLabels...)
		}
	}
	ch <- prometheus.MustNewConstMetric(
		libvirtDomainMemoryStatUsedPercentDesc,
		prometheus.GaugeValue,
		(float64(available)-float64(usable))/(float64(available)/float64(100)),
		promLabels...)

	return
}

func CollectDomainVCPUInfo(ch chan<- prometheus.Metric, l *libvirt.Libvirt, domain domainMeta, promLabels []string, logger *slog.Logger, timeout time.Duration) (err error, hasTimedOut bool) {
	var data []libvirt.DomainStatsRecord

	chRes := make(chan DomainStatsRecord, 1)

	go connectGetAllDomainStats(l, domain, libvirt.DomainStatsVCPU, chRes)

	select {
	case res := <-chRes:
		if res.err != nil {
			return res.err, false
		}
		data = res.DomainStatsRecord
	case <-time.After(time.Duration(timeout) * time.Second):
		return fmt.Errorf("call to ConnectGetAllDomainStats with DomainStatsVCPU flag has timed out"), true
	}

	current := regexp.MustCompile("vcpu.current")
	maximum := regexp.MustCompile("vcpu.maximum")
	vcpu_metrics := regexp.MustCompile(`vcpu\.\d+\.\w+`)
	for _, stat := range data {
		for _, param := range stat.Params {
			switch true {
			case current.MatchString(param.Field):
				metric_value := param.Value.I.(uint32)
				ch <- prometheus.MustNewConstMetric(
					libvirtDomainVCPUStatsCurrent,
					prometheus.GaugeValue,
					float64(metric_value),
					promLabels...)
			case maximum.MatchString(param.Field):
				metric_value := param.Value.I.(uint32)
				ch <- prometheus.MustNewConstMetric(
					libvirtDomainVCPUStatsMaximum,
					prometheus.GaugeValue,
					float64(metric_value),
					promLabels...)
			case vcpu_metrics.MatchString(param.Field):
				r := regexp.MustCompile(`vcpu\.(\d+)\.(\w+)`)
				match := r.FindStringSubmatch(param.Field)
				promVCPULabels := append(promLabels, match[1])
				switch match[2] {
				case "state":
					metric_value := param.Value.I.(int32)
					ch <- prometheus.MustNewConstMetric(
						libvirtDomainVCPUStatsState,
						prometheus.GaugeValue,
						float64(metric_value),
						promVCPULabels...)
				case "time":
					metric_value := param.Value.I.(uint64)
					ch <- prometheus.MustNewConstMetric(
						libvirtDomainVCPUStatsTime,
						prometheus.CounterValue,
						float64(metric_value)/1e9,
						promVCPULabels...)
				case "wait":
					metric_value := param.Value.I.(uint64)
					ch <- prometheus.MustNewConstMetric(
						libvirtDomainVCPUStatsWait,
						prometheus.CounterValue,
						float64(metric_value)/1e9,
						promVCPULabels...)
				case "delay":
					metric_value := param.Value.I.(uint64)
					ch <- prometheus.MustNewConstMetric(
						libvirtDomainVCPUStatsDelay,
						prometheus.CounterValue,
						float64(metric_value)/1e9,
						promVCPULabels...)
				}
			}
		}
	}

	return
}

func CollectStoragePoolInfo(ch chan<- prometheus.Metric, l *libvirt.Libvirt, pool libvirt.StoragePool, logger *slog.Logger, timeout time.Duration) (err error, hasTimedOut bool) {
	// Report storage pool metrics
	var (
		pState                             uint8
		pCapacity, pAllocation, pAvailable uint64
	)

	type rStoragePoolGetInfo struct {
		pState                             uint8
		pCapacity, pAllocation, pAvailable uint64
		err                                error
	}

	chrStoragePoolGetInfo := make(chan rStoragePoolGetInfo, 1)
	go func() {
		var data rStoragePoolGetInfo
		data.pState, data.pCapacity, data.pAllocation, data.pAvailable, data.err = l.StoragePoolGetInfo(pool)
		chrStoragePoolGetInfo <- data
	}()

	select {
	case res := <-chrStoragePoolGetInfo:
		if res.err != nil {
			return res.err, false
		}
		pState = res.pState
		pCapacity = res.pCapacity
		pAllocation = res.pAllocation
		pAvailable = res.pAvailable
	case <-time.After(time.Duration(timeout) * time.Second):
		return fmt.Errorf("call to StoragePoolGetInfo has timed out"), true
	}

	promLabels := []string{
		pool.Name,
	}
	ch <- prometheus.MustNewConstMetric(
		libvirtStoragePoolState,
		prometheus.GaugeValue,
		float64(pState),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtStoragePoolCapacity,
		prometheus.GaugeValue,
		float64(pCapacity),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtStoragePoolAllocation,
		prometheus.GaugeValue,
		float64(pAllocation),
		promLabels...)
	ch <- prometheus.MustNewConstMetric(
		libvirtStoragePoolAvailable,
		prometheus.GaugeValue,
		float64(pAvailable),
		promLabels...)

	return
}

// Describe returns metadata for all Prometheus metrics that may be exported.
func (e *LibvirtExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- libvirtUpDesc
	ch <- libvirtDomainNumbers

	ch <- libvirtDomainInfoDesc
	ch <- libvirtDomainOpenstackInfoDesc

	//domain info
	ch <- libvirtDomainState
	ch <- libvirtDomainInfoMaxMemDesc
	ch <- libvirtDomainInfoMemoryDesc
	ch <- libvirtDomainInfoNrVirtCpuDesc
	ch <- libvirtDomainInfoCpuTimeDesc

	//domain block
	ch <- libvirtDomainBlockStatsInfo
	ch <- libvirtDomainBlockStatsRdBytesDesc
	ch <- libvirtDomainBlockStatsRdReqDesc
	ch <- libvirtDomainBlockStatsWrBytesDesc
	ch <- libvirtDomainBlockStatsWrReqDesc
	ch <- libvirtDomainBlockRdTotalTimeSecondsDesc
	ch <- libvirtDomainBlockWrTotalTimesDesc
	ch <- libvirtDomainBlockFlushReqDesc
	ch <- libvirtDomainBlockFlushTotalTimeSecondsDesc
	ch <- libvirtDomainBlockCapacityBytesDesc

	//domain interface
	ch <- libvirtDomainInterfaceInfo
	ch <- libvirtDomainInterfaceRxBytesDesc
	ch <- libvirtDomainInterfaceRxPacketsDesc
	ch <- libvirtDomainInterfaceRxErrsDesc
	ch <- libvirtDomainInterfaceRxDropDesc
	ch <- libvirtDomainInterfaceTxBytesDesc
	ch <- libvirtDomainInterfaceTxPacketsDesc
	ch <- libvirtDomainInterfaceTxErrsDesc
	ch <- libvirtDomainInterfaceTxDropDesc

	//domain job
	ch <- libvirtDomainJobTypeDesc
	ch <- libvirtDomainJobTimeElapsedDesc
	ch <- libvirtDomainJobTimeRemainingDesc
	ch <- libvirtDomainJobDataTotalDesc
	ch <- libvirtDomainJobDataProcessedDesc
	ch <- libvirtDomainJobDataRemainingDesc
	ch <- libvirtDomainJobMemTotalDesc
	ch <- libvirtDomainJobMemProcessedDesc
	ch <- libvirtDomainJobMemRemainingDesc
	ch <- libvirtDomainJobFileTotalDesc
	ch <- libvirtDomainJobFileProcessedDesc
	ch <- libvirtDomainJobFileRemainingDesc

	//domain mem stat
	ch <- libvirtDomainMemoryStatsCurrentBalloonBytesDesc
	ch <- libvirtDomainMemoryStatsMaximumBytesDesc
	ch <- libvirtDomainMemoryStatsSwapInBytesDesc
	ch <- libvirtDomainMemoryStatsSwapOutBytesDesc
	ch <- libvirtDomainMemoryStatsMajorFaultTotalDesc
	ch <- libvirtDomainMemoryStatsMinorFaultTotalDesc
	ch <- libvirtDomainMemoryStatsUnusedBytesDesc
	ch <- libvirtDomainMemoryStatsAvailableInBytesDesc
	ch <- libvirtDomainMemoryStatsUsableBytesDesc
	ch <- libvirtDomainMemoryStatsLastUpdateDesc
	ch <- libvirtDomainMemoryStatsDiskCachesBytesDesc
	ch <- libvirtDomainMemoryStatsHugeTLBPageAllocTotalDesc
	ch <- libvirtDomainMemoryStatsHugeTLBPageFailTotalDesc
	ch <- libvirtDomainMemoryStatsRssBytesDesc

	//domain vcpu stats
	ch <- libvirtDomainVCPUStatsCurrent
	ch <- libvirtDomainVCPUStatsMaximum
	ch <- libvirtDomainVCPUStatsState
	ch <- libvirtDomainVCPUStatsTime
	ch <- libvirtDomainVCPUStatsWait
	ch <- libvirtDomainVCPUStatsDelay

	//storage pool metrics
	ch <- libvirtStoragePoolState
	ch <- libvirtStoragePoolCapacity
	ch <- libvirtStoragePoolAllocation
	ch <- libvirtStoragePoolAvailable
}
