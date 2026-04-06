local g = import 'github.com/grafana/grafonnet/gen/grafonnet-v11.4.0/main.libsonnet';

{
  power_state: g.query.prometheus.new('${datasource}', 'libvirt_domain_info_state{domain="$dom_id"}'),
  cpu_allocated: g.query.prometheus.new('${datasource}', 'libvirt_domain_vcpu_current{domain="$dom_id"}'),
  memory_allocated: g.query.prometheus.new('${datasource}', 'libvirt_domain_memory_stats_maximum_bytes{domain="$dom_id"}'),
  disk_count: g.query.prometheus.new('${datasource}', 'count(libvirt_domain_block_stats_info{domain="$dom_id"})'),
  network_port_count: g.query.prometheus.new('${datasource}', 'count(libvirt_domain_interface_stats_info{domain="$dom_id"})'),

  cpu_usage_percentage: g.query.prometheus.new(
    '${datasource}',
    '(rate(libvirt_domain_info_cpu_time_seconds_total{domain="$dom_id"}[$__rate_interval])/libvirt_domain_vcpu_current{domain="$dom_id"}) * 100'
  ) + g.query.prometheus.withLegendFormat('{{domain}}'),
  cpu_steal_pecentage: g.query.prometheus.new(
    '${datasource}',
    '(sum by (domain) (rate(libvirt_domain_vcpu_delay_seconds_total{domain="$dom_id"}[$__rate_interval]))/sum by (domain) (rate(libvirt_domain_vcpu_time_seconds_total{domain="$dom_id"}[$__rate_interval]))) * 100'
  ) + g.query.prometheus.withLegendFormat('{{domain}}'),

  memory_usage_percentage: g.query.prometheus.new(
    '${datasource}',
    'libvirt_domain_memory_stats_used_percent{domain="$dom_id"}'
  ) + g.query.prometheus.withLegendFormat('{{domain}}'),

  memory_swap_bytes: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain)(\n  rate(libvirt_domain_memory_stats_swap_in_bytes{domain="$dom_id"}[$__rate_interval])\n+\n  rate(libvirt_domain_memory_stats_swap_out_bytes{domain="$dom_id"}[$__rate_interval])\n)\n'
  ) + g.query.prometheus.withLegendFormat('{{domain}}'),

  storage_iops_total: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device) (\n  rate(libvirt_domain_block_stats_read_requests_total{domain="$dom_id"}[$__rate_interval])\n  +\n  rate(libvirt_domain_block_stats_write_requests_total{domain="$dom_id"}[$__rate_interval])\n) '
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  storage_iops_read: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device) (\n  rate({__name__=~"libvirt_domain_block_stats_read_requests_total", domain="$dom_id"}[$__rate_interval])\n) '
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  storage_iops_write: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device) (\n  rate({__name__=~"libvirt_domain_block_stats_write_requests_total", domain="$dom_id"}[$__rate_interval])\n) '
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  storage_throughput_total: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device) (\n  rate(libvirt_domain_block_stats_read_bytes_total{domain="$dom_id"}[$__rate_interval])\n  +\n  rate(libvirt_domain_block_stats_write_bytes_total{domain="$dom_id"}[$__rate_interval])\n) '
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  storage_throughput_read: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device) (\n  rate({__name__=~"libvirt_domain_block_stats_read_bytes_total", domain="$dom_id"}[$__rate_interval])\n) '
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  storage_throughput_write: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device) (\n  rate({__name__=~"libvirt_domain_block_stats_write_bytes_total", domain="$dom_id"}[$__rate_interval])\n) '
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  storage_latency_read: g.query.prometheus.new(
    '${datasource}',
    '(\n  sum by (domain, target_device) (\n    rate({__name__=~"libvirt_domain_block_stats_read_time_seconds_total", domain="$dom_id"}[$__rate_interval])\n  )\n  /\n  sum by (domain, target_device) (\n    rate({__name__=~"libvirt_domain_block_stats_read_requests_total", domain="$dom_id"}[$__rate_interval])\n  )\n) * 1000 '
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  storage_latency_write: g.query.prometheus.new(
    '${datasource}',
    '(\n  sum by (domain, target_device) (\n    rate({__name__=~"libvirt_domain_block_stats_write_time_seconds_total", domain="$dom_id"}[$__rate_interval])\n  )\n  /\n  sum by (domain, target_device) (\n    rate({__name__=~"libvirt_domain_block_stats_write_requests_total", domain="$dom_id"}[$__rate_interval])\n  )\n) * 1000 '
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  storage_average_block_size: g.query.prometheus.new(
    '${datasource}',
    '(\n  sum by (domain, target_device) (\n    rate(libvirt_domain_block_stats_read_bytes_total{domain="$dom_id"}[$__rate_interval])\n    +\n    rate(libvirt_domain_block_stats_write_bytes_total{domain="$dom_id"}[$__rate_interval])\n  )\n  /\n  sum by (domain, target_device) (\n    rate(libvirt_domain_block_stats_read_requests_total{domain="$dom_id"}[$__rate_interval])\n    +\n    rate(libvirt_domain_block_stats_write_requests_total{domain="$dom_id"}[$__rate_interval])\n  )\n) '
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  newtork_throughput_total: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device)(\n  rate(libvirt_domain_interface_stats_receive_bytes_total{domain="$dom_id"}[$__rate_interval])\n+\n  rate(libvirt_domain_interface_stats_transmit_bytes_total{domain="$dom_id"}[$__rate_interval])\n)\n'
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  newtork_throughput_receive: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device)(\n  rate(libvirt_domain_interface_stats_receive_bytes_total{domain="$dom_id"}[$__rate_interval])\n)\n'
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  newtork_throughput_transmit: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device)(\n  rate(libvirt_domain_interface_stats_transmit_bytes_total{domain="$dom_id"}[$__rate_interval])\n)\n'
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  network_packet_total: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device)(\n  rate(libvirt_domain_interface_stats_transmit_packets_total{domain="$dom_id"}[$__rate_interval])\n+\n  rate(libvirt_domain_interface_stats_receive_packets_total{domain="$dom_id"}[$__rate_interval])\n)\n'
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  network_packet_receive: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device)(\n  rate(libvirt_domain_interface_stats_receive_packets_total{domain="$dom_id"}[$__rate_interval])\n)\n'
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  network_packet_transmit: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device)(\n  rate(libvirt_domain_interface_stats_transmit_packets_total{domain="$dom_id"}[$__rate_interval])\n)\n'
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  network_errors_receive: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device)(\n  rate(libvirt_domain_interface_stats_receive_errors_total{domain="$dom_id"}[$__rate_interval])\n)\n'
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  network_errors_transmit: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device)(\n  rate(libvirt_domain_interface_stats_transmit_errors_total{domain="$dom_id"}[$__rate_interval])\n)\n'
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  network_drops_receive: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device)(\n  rate(libvirt_domain_interface_stats_receive_drops_total{domain="$dom_id"}[$__rate_interval])\n)'
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

  network_drops_transmit: g.query.prometheus.new(
    '${datasource}',
    'sum by (domain, target_device)(\n  rate(libvirt_domain_interface_stats_receive_drops_total{domain="$dom_id"}[$__rate_interval])\n)'
  ) + g.query.prometheus.withLegendFormat('{{target_device}}'),

}
