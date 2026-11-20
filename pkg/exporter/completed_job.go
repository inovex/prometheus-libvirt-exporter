package exporter

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
)

// Statistics of the last completed job of a domain (virDomainGetJobStats with
// VIR_DOMAIN_JOB_STATS_COMPLETED). After a live migration, the QEMU driver of
// the destination host keeps the statistics sent by the source host, so the
// migration statistics (including the final downtime) of a VM are exposed by
// the exporter running on the destination host, until the next job of the domain.
var completedJobLabels = []string{"domain", "operation", "result"}

var (
	libvirtDomainCompletedJobInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "domain_completed_job", "info"),
		"Last completed job of the domain (e.g. a live migration), its operation and result as labels.",
		completedJobLabels,
		nil)
)

// completedJobField maps a typed parameter returned by virDomainGetJobStats to a Prometheus metric.
type completedJobField struct {
	field string
	desc  *prometheus.Desc
	scale float64
}

func newCompletedJobField(field, name, help string, scale float64) completedJobField {
	return completedJobField{
		field: field,
		desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "domain_completed_job", name),
			help,
			completedJobLabels,
			nil),
		scale: scale,
	}
}

const msToSeconds = 1e-3

// see VIR_DOMAIN_JOB_* in https://libvirt.org/html/libvirt-libvirt-domain.html
var completedJobFields = []completedJobField{
	newCompletedJobField("time_elapsed", "time_elapsed_seconds", "Total duration of the last completed job.", msToSeconds),
	newCompletedJobField("time_elapsed_net", "time_elapsed_net_seconds", "Total duration of the last completed job, without the time needed to transfer statistics between migration hosts.", msToSeconds),
	newCompletedJobField("downtime", "downtime_seconds", "Downtime of the domain during the last completed migration (time between pausing the domain on the source and resuming it on the destination).", msToSeconds),
	newCompletedJobField("downtime_net", "downtime_net_seconds", "Downtime of the domain during the last completed migration, without the time needed to transfer statistics between migration hosts.", msToSeconds),
	newCompletedJobField("setup_time", "setup_time_seconds", "Time spent setting up the last completed migration before memory transfer started.", msToSeconds),
	newCompletedJobField("data_total", "data_total_bytes", "Total amount of data (memory + disks) to transfer during the last completed job.", 1),
	newCompletedJobField("data_processed", "data_processed_bytes", "Amount of data (memory + disks) transferred during the last completed job.", 1),
	newCompletedJobField("data_remaining", "data_remaining_bytes", "Amount of data (memory + disks) left to transfer when the last job completed.", 1),
	newCompletedJobField("memory_total", "memory_total_bytes", "Total amount of memory to transfer during the last completed job.", 1),
	newCompletedJobField("memory_processed", "memory_processed_bytes", "Amount of memory transferred during the last completed job.", 1),
	newCompletedJobField("memory_remaining", "memory_remaining_bytes", "Amount of memory left to transfer when the last job completed.", 1),
	newCompletedJobField("memory_constant", "memory_constant_pages", "Number of pages filled with a constant byte (zero pages) during the last completed job.", 1),
	newCompletedJobField("memory_normal", "memory_normal_pages", "Number of pages transferred without compression during the last completed job.", 1),
	newCompletedJobField("memory_normal_bytes", "memory_normal_bytes", "Amount of memory transferred as normal (uncompressed, non zero) pages during the last completed job.", 1),
	newCompletedJobField("memory_bps", "memory_bytes_per_second", "Memory transfer bandwidth during the last completed job.", 1),
	newCompletedJobField("memory_dirty_rate", "memory_dirty_rate_pages_per_second", "Rate at which the domain dirtied memory pages during the last completed migration.", 1),
	newCompletedJobField("memory_page_size", "memory_page_size_bytes", "Size of a memory page in the last completed job.", 1),
	newCompletedJobField("memory_iteration", "memory_iterations", "Number of memory transfer iterations of the last completed migration.", 1),
	newCompletedJobField("memory_postcopy_requests", "memory_postcopy_requests", "Number of page faults the destination requested from the source during post-copy of the last completed migration.", 1),
	newCompletedJobField("disk_total", "disk_total_bytes", "Total amount of disk data to transfer during the last completed job.", 1),
	newCompletedJobField("disk_processed", "disk_processed_bytes", "Amount of disk data transferred during the last completed job.", 1),
	newCompletedJobField("disk_remaining", "disk_remaining_bytes", "Amount of disk data left to transfer when the last job completed.", 1),
	newCompletedJobField("disk_bps", "disk_bytes_per_second", "Disk transfer bandwidth during the last completed job.", 1),
	newCompletedJobField("auto_converge_throttle", "auto_converge_throttle_percent", "Percentage of vCPU time throttled by auto-converge during the last completed migration.", 1),
}

var jobOperationNames = map[libvirt.DomainJobOperation]string{
	libvirt.DomainJobOperationStrUnknown:        "unknown",
	libvirt.DomainJobOperationStrStart:          "start",
	libvirt.DomainJobOperationStrSave:           "save",
	libvirt.DomainJobOperationStrRestore:        "restore",
	libvirt.DomainJobOperationStrMigrationIn:    "migration_in",
	libvirt.DomainJobOperationStrMigrationOut:   "migration_out",
	libvirt.DomainJobOperationStrSnapshot:       "snapshot",
	libvirt.DomainJobOperationStrSnapshotRevert: "snapshot_revert",
	libvirt.DomainJobOperationStrDump:           "dump",
	libvirt.DomainJobOperationStrBackup:         "backup",
	libvirt.DomainJobOperationStrSnapshotDelete: "snapshot_delete",
}

var jobResultNames = map[libvirt.DomainJobType]string{
	libvirt.DomainJobCompleted: "completed",
	libvirt.DomainJobFailed:    "failed",
	libvirt.DomainJobCancelled: "cancelled",
}

// typedParamToFloat converts a numeric libvirt typed parameter value to float64.
func typedParamToFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case int32:
		return float64(n), true
	case uint32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float64:
		return n, true
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}

// completedJobMetrics builds the metrics of the last completed job from the result of virDomainGetJobStats.
func completedJobMetrics(domainName string, jobType int32, params []libvirt.TypedParam) []prometheus.Metric {
	result, ok := jobResultNames[libvirt.DomainJobType(jobType)]
	if !ok {
		// VIR_DOMAIN_JOB_NONE: no completed job statistics for this domain
		return nil
	}

	values := make(map[string]float64, len(params))
	operation := jobOperationNames[libvirt.DomainJobOperationStrUnknown]
	for _, param := range params {
		v, ok := typedParamToFloat(param.Value.I)
		if !ok {
			continue
		}
		if param.Field == "operation" {
			if name, found := jobOperationNames[libvirt.DomainJobOperation(v)]; found {
				operation = name
			}
			continue
		}
		values[param.Field] = v
	}

	labels := []string{domainName, operation, result}
	metrics := []prometheus.Metric{
		prometheus.MustNewConstMetric(libvirtDomainCompletedJobInfoDesc, prometheus.GaugeValue, 1, labels...),
	}
	for _, f := range completedJobFields {
		if v, found := values[f.field]; found {
			metrics = append(metrics, prometheus.MustNewConstMetric(f.desc, prometheus.GaugeValue, v*f.scale, labels...))
		}
	}
	return metrics
}

// CollectDomainCompletedJobStats exports the statistics of the last completed job of a domain, e.g. a live migration.
func CollectDomainCompletedJobStats(ch chan<- prometheus.Metric, l *libvirt.Libvirt, domain domainMeta, promLabels []string, logger *slog.Logger, timeout time.Duration) (err error, hasTimedOut bool) {
	type rDomainGetJobStats struct {
		rType   int32
		rParams []libvirt.TypedParam
		err     error
	}

	chRes := make(chan rDomainGetJobStats, 1)
	go func() {
		var data rDomainGetJobStats
		// KEEP_COMPLETED: reading the completed job statistics must not discard them
		data.rType, data.rParams, data.err = l.DomainGetJobStats(domain.libvirtDomain, libvirt.DomainJobStatsCompleted|libvirt.DomainJobStatsKeepCompleted)
		chRes <- data
	}()

	select {
	case res := <-chRes:
		if res.err != nil {
			if libvirtErr, ok := res.err.(libvirt.Error); ok &&
				(libvirtErr.Code == uint32(libvirt.ErrOperationUnsupported) || libvirtErr.Code == uint32(libvirt.ErrNoSupport) || libvirtErr.Code == uint32(libvirt.ErrInvalidArg)) {
				// hypervisor driver or libvirt version without completed job statistics
				logger.Debug("completed job statistics not supported", "domain", domain.domainName, "msg", res.err)
				return nil, false
			}
			return res.err, false
		}
		for _, m := range completedJobMetrics(domain.domainName, res.rType, res.rParams) {
			ch <- m
		}
	case <-time.After(timeout):
		return fmt.Errorf("call to DomainGetJobStats has timed out"), true
	}

	return nil, false
}

func describeCompletedJobStats(ch chan<- *prometheus.Desc) {
	ch <- libvirtDomainCompletedJobInfoDesc
	for _, f := range completedJobFields {
		ch <- f.desc
	}
}
