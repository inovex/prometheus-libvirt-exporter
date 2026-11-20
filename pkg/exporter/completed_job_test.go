package exporter

import (
	"strings"
	"testing"

	"github.com/digitalocean/go-libvirt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

type staticCollector []prometheus.Metric

func (c staticCollector) Describe(ch chan<- *prometheus.Desc) { prometheus.DescribeByCollect(c, ch) }
func (c staticCollector) Collect(ch chan<- prometheus.Metric) {
	for _, m := range c {
		ch <- m
	}
}

func param(field string, v interface{}) libvirt.TypedParam {
	return libvirt.TypedParam{Field: field, Value: libvirt.TypedParamValue{I: v}}
}

func TestCompletedJobMetricsMigration(t *testing.T) {
	// statistics as returned on the destination host after a live migration
	params := []libvirt.TypedParam{
		param("operation", int32(libvirt.DomainJobOperationStrMigrationIn)),
		param("time_elapsed", uint64(12345)),
		param("downtime", uint64(42)),
		param("downtime_net", uint64(40)),
		param("setup_time", uint64(15)),
		param("memory_processed", uint64(4294967296)),
		param("memory_iteration", uint64(3)),
		param("auto_converge_throttle", int32(20)),
		param("errmsg", "ignored"),
		param("unknown_field", uint64(1)),
	}

	metrics := completedJobMetrics("instance-00000001", int32(libvirt.DomainJobCompleted), params)

	expected := `
# HELP libvirt_domain_completed_job_auto_converge_throttle_percent Percentage of vCPU time throttled by auto-converge during the last completed migration.
# TYPE libvirt_domain_completed_job_auto_converge_throttle_percent gauge
libvirt_domain_completed_job_auto_converge_throttle_percent{domain="instance-00000001",operation="migration_in",result="completed"} 20
# HELP libvirt_domain_completed_job_downtime_net_seconds Downtime of the domain during the last completed migration, without the time needed to transfer statistics between migration hosts.
# TYPE libvirt_domain_completed_job_downtime_net_seconds gauge
libvirt_domain_completed_job_downtime_net_seconds{domain="instance-00000001",operation="migration_in",result="completed"} 0.04
# HELP libvirt_domain_completed_job_downtime_seconds Downtime of the domain during the last completed migration (time between pausing the domain on the source and resuming it on the destination).
# TYPE libvirt_domain_completed_job_downtime_seconds gauge
libvirt_domain_completed_job_downtime_seconds{domain="instance-00000001",operation="migration_in",result="completed"} 0.042
# HELP libvirt_domain_completed_job_info Last completed job of the domain (e.g. a live migration), its operation and result as labels.
# TYPE libvirt_domain_completed_job_info gauge
libvirt_domain_completed_job_info{domain="instance-00000001",operation="migration_in",result="completed"} 1
# HELP libvirt_domain_completed_job_memory_iterations Number of memory transfer iterations of the last completed migration.
# TYPE libvirt_domain_completed_job_memory_iterations gauge
libvirt_domain_completed_job_memory_iterations{domain="instance-00000001",operation="migration_in",result="completed"} 3
# HELP libvirt_domain_completed_job_memory_processed_bytes Amount of memory transferred during the last completed job.
# TYPE libvirt_domain_completed_job_memory_processed_bytes gauge
libvirt_domain_completed_job_memory_processed_bytes{domain="instance-00000001",operation="migration_in",result="completed"} 4.294967296e+09
# HELP libvirt_domain_completed_job_setup_time_seconds Time spent setting up the last completed migration before memory transfer started.
# TYPE libvirt_domain_completed_job_setup_time_seconds gauge
libvirt_domain_completed_job_setup_time_seconds{domain="instance-00000001",operation="migration_in",result="completed"} 0.015
# HELP libvirt_domain_completed_job_time_elapsed_seconds Total duration of the last completed job.
# TYPE libvirt_domain_completed_job_time_elapsed_seconds gauge
libvirt_domain_completed_job_time_elapsed_seconds{domain="instance-00000001",operation="migration_in",result="completed"} 12.345
`
	assert.NoError(t, testutil.CollectAndCompare(staticCollector(metrics), strings.NewReader(expected)))
}

func TestCompletedJobMetricsFailedMigration(t *testing.T) {
	params := []libvirt.TypedParam{
		param("operation", int32(libvirt.DomainJobOperationStrMigrationOut)),
		param("time_elapsed", uint64(500)),
	}
	metrics := completedJobMetrics("instance-00000002", int32(libvirt.DomainJobFailed), params)

	expected := `
# HELP libvirt_domain_completed_job_info Last completed job of the domain (e.g. a live migration), its operation and result as labels.
# TYPE libvirt_domain_completed_job_info gauge
libvirt_domain_completed_job_info{domain="instance-00000002",operation="migration_out",result="failed"} 1
`
	assert.NoError(t, testutil.CollectAndCompare(staticCollector(metrics), strings.NewReader(expected), "libvirt_domain_completed_job_info"))
}

func TestCompletedJobMetricsNoJob(t *testing.T) {
	assert.Empty(t, completedJobMetrics("instance-00000003", int32(libvirt.DomainJobNone), nil))
}
