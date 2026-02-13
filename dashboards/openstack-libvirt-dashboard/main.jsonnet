local g = import 'github.com/grafana/grafonnet/gen/grafonnet-v11.4.0/main.libsonnet';
local query = import 'lib/query.jsonnet';
local templates = import 'lib/templates.jsonnet';
local vars = import 'lib/variables.jsonnet';


local summaryPanels = {
  powerState: templates.vmStatPanel(
    title='VM • Power State',
    targets=[query.power_state],
    description='Shows the current power state of the VM. Requires the VM to be powered-on to return a value.',
    unit=null,
    colorMode='value',
    mappings=[
      {
        type: 'value',
        options: {
          '0': { color: 'red', text: 'NO STATE' },
          '1': { color: 'green', text: 'ON' },
          '2': { color: 'orange', text: 'BLOCKED' },
          '3': { color: 'orange', text: 'PAUSED' },
          '4': { color: 'orange', text: 'SHUTTING DOWN' },
          '5': { color: 'red', text: 'OFF' },
          '6': { color: 'red', text: 'CRASHED' },
          '7': { color: 'red', text: 'SUSPENDED' },
        },
      },
    ]
  ),

  cpuAllocated: templates.vmStatPanel(
    title='CPU • Allocated vCPUs',
    targets=[query.cpu_allocated],
    description='Shows the current number of allocated vCPUs for the VM.',
    unit=null,
    colorMode='fixed',
    mappings=[],
    noThresholds=true
  ),

  memoryAllocated: templates.vmStatPanel(
    title='Memory • Allocated RAM',
    targets=[query.memory_allocated],
    description='Shows the current allocated memory for the VM.',
    unit='bytes',
    colorMode='fixed',
    mappings=[],
    noThresholds=true
  ),

  diskCount: templates.vmStatPanel(
    title='Storage • Disk Count',
    targets=[query.disk_count],
    description='Shows the number of disks attached to the VM.',
    unit=null,
    colorMode='fixed',
    mappings=[],
    noThresholds=true
  ),

  networkPortCount: templates.vmStatPanel(
    title='Network • Port Count',
    targets=[query.network_port_count],
    description='Shows the number of network ports attached to the VM.',
    unit=null,
    colorMode='fixed',
    mappings=[],
    noThresholds=true
  ),
};

local cpuPanel = {
  cpuUsage: templates.timeSeriesPanel(
    title='CPU • Usage %',
    targets=[query.cpu_usage_percentage],
    unit='percent',
    description='Percentage of allocated CPU capacity actively used by the VM.\n\n- 0–80% → Normal <br>\n- 80-90% → Heavy load <br>\n- 90% sustained → CPU pressure likely\n\nHigh utilization + scheduling delay indicates host contention.',
  ) {
    fieldConfig+: {
      defaults+: {
        thresholds: {
          mode: 'absolute',
          steps: [
            { color: 'green', value: null },
            { color: 'yellow', value: 80 },
            { color: 'red', value: 90 },
          ],
        },
        custom: {
          thresholdsStyle: { mode: 'area' },
        },
      },
    },
  },
  cpuSteal: templates.timeSeriesPanel(
    title='CPU • Steal Time %',
    targets=[query.cpu_steal_pecentage],
    unit='percent',
    description='Time the VM was runnable but not scheduled by the hypervisor.\n\n- 0–1% → Healthy <br>\n- 1–3% → Light contention <br>\n- 3–5% → Moderate contention <br>\n- 5% sustained → Requires Operator attention <br>\n\nHigh delay + high utilization = hypervisor contention.',
  ) {
    fieldConfig+: {
      defaults+: {
        thresholds: {
          mode: 'absolute',
          steps: [
            { color: 'green', value: null },
            { color: 'yellow', value: 1 },
            { color: 'orange', value: 3 },
            { color: 'red', value: 5 },
          ],
        },
        custom: {
          thresholdsStyle: { mode: 'area' },
        },
      },
    },
  },
};


local memoryPanel = {
  memoryUsage: templates.timeSeriesPanel(
    title='Memory • Usage %',
    targets=[query.memory_usage_percentage],
    unit='percent',
    description='Percentage of allocated memory currently used inside the guest OS.',
  ) + {
    fieldConfig+: {
      defaults+: {
        thresholds: {
          mode: 'absolute',
          steps: [
            { color: 'green', value: null },
            { color: 'yellow', value: 80 },
            { color: 'red', value: 90 },
          ],
        },
        custom: {
          thresholdsStyle: { mode: 'area' },
        },
      },
    },
  },
  memorySwap: templates.timeSeriesPanel(
    title='Memory • Total Swap Activity',
    targets=[query.memory_swap_bytes],
    unit='binBps',
    description='Amount of data swapped into RAM from disk per second.\n\nSustained non-zero values indicate active memory pressure inside the guest.\n\n- 0 → No swap activity <br>\n- <1 MB/s → Light pressure\n- 1–10 MB/s sustained → Moderate pressure\n- 10 MB/s sustained → Likely performance impact',
  ) + {
    fieldConfig+: {
      defaults+: {
        thresholds: {
          mode: 'absolute',
          steps: [
            { color: 'green', value: null },
            { color: 'orange', value: 1024 * 1024 },
            { color: 'red', value: 10 * 1024 * 1024 },
          ],
        },
        custom: {
          thresholdsStyle: { mode: 'area' },
        },
      },
    },
  },
};

local storagePanel = {
  iopsTotal: templates.timeSeriesPanel(
    title='Storage • Total IOPS',
    targets=[query.storage_iops_total],
    unit='ops/s',
    description='Total read + write operations per second per disk.\n\nHigh IOPS alone is fine.\nHigh IOPS + increasing latency indicates storage saturation.',
  ),
  iopsRead: templates.timeSeriesPanel(
    title='Storage • Read IOPS',
    targets=[query.storage_iops_read],
    unit='ops/s',
    description='Number of read operations per second across all VM disks.',
  ),
  iopsWrite: templates.timeSeriesPanel(
    title='Storage • Write IOPS',
    targets=[query.storage_iops_write],
    unit='ops/s',
    description='Number of write operations per second across all VM disks.',
  ),
  throughputTotal: templates.timeSeriesPanel(
    title='Storage • Total Throughput',
    targets=[query.storage_throughput_total],
    unit='binBps',
    description='Combined read and write data rate (bytes/sec).\n\nHigh throughput + high latency suggests backend limits / qos limits.',
  ),
  throughputRead: templates.timeSeriesPanel(
    title='Storage • Read Throughput',
    targets=[query.storage_throughput_read],
    unit='binBps',
    description='Read throughput in bytes per second across all VM disks.',
  ),
  throughputWrite: templates.timeSeriesPanel(
    title='Storage • Write Throughput',
    targets=[query.storage_throughput_write],
    unit='binBps',
    description='Write throughput in bytes per second across all VM disks.',
  ),
  latencyRead: templates.timeSeriesPanel(
    title='Storage • Read Latency',
    targets=[query.storage_latency_read],
    unit='ms',
    description='Average time to complete read operations.\n\n- <5 ms → Excellent <br>\n- 5–25 ms → Acceptable <br>\n- 25-35 ms → Workload may be impacted <br>\n- 35 ms sustained → Backend pressure / Reached QOS Limits\n',
  ) + {
    fieldConfig+: {
      defaults+: {
        thresholds: {
          mode: 'absolute',
          steps: [
            { color: 'green', value: null },
            { color: 'lightgreen', value: 5 },
            { color: 'orange', value: 25 },
            { color: 'red', value: 35 },
          ],
        },
        custom: {
          thresholdsStyle: { mode: 'area' },
        },
      },
    },
  },
  latencyWrite: templates.timeSeriesPanel(
    title='Storage • Write Latency',
    targets=[query.storage_latency_write],
    unit='ms',
    description='Average time to complete write operations.\n\n- <8 ms → Excellent <br>\n- 8–25 ms → Acceptable <br>\n- 25-35 ms → Workload may be impacted <br>\n- 35 ms sustained → Backend pressure / Reached QOS Limits\n',
  ) + {
    fieldConfig+: {
      defaults+: {
        thresholds: {
          mode: 'absolute',
          steps: [
            { color: 'green', value: null },
            { color: 'lightgreen', value: 8 },
            { color: 'orange', value: 25 },
            { color: 'red', value: 35 },
          ],
        },
        custom: {
          thresholdsStyle: { mode: 'area' },
        },
      },
    },
  },
  averageBlockSize: templates.timeSeriesPanel(
    title='Storage • Average Block Size',
    targets=[query.storage_average_block_size],
    unit='bytes',
    description='Average size per I/O operation.\n\nSmall values → IOPS-heavy workload <br>\nLarge values → throughput-heavy workload',
  ),
};


local networkPanel = {
  networkThroughputTotal: templates.timeSeriesPanel(
    title='Network • Total Throughput',
    targets=[query.newtork_throughput_total],
    unit='binBps',
    description='Total network throughput in bytes per second across all VM interfaces.',
  ),
  networkThroughputReceive: templates.timeSeriesPanel(
    title='Network • Receive Throughput',
    targets=[query.newtork_throughput_receive],
    unit='binBps',
    description='Network receive throughput in bytes per second across all VM interfaces.',
  ),
  networkThroughputTransmit: templates.timeSeriesPanel(
    title='Network • Transmit Throughput',
    targets=[query.newtork_throughput_transmit],
    unit='binBps',
    description='Network transmit throughput in bytes per second across all VM interfaces.',
  ),
  networkPacketTotal: templates.timeSeriesPanel(
    title='Network • Total Packets',
    targets=[query.network_packet_total],
    unit='pps',
    description='Total network packets per second across all VM interfaces.',
  ),
  networkPacketReceive: templates.timeSeriesPanel(
    title='Network • Receive Packets',
    targets=[query.network_packet_receive],
    unit='pps',
    description='Network receive packets per second across all VM interfaces.',
  ),
  networkPacketTransmit: templates.timeSeriesPanel(
    title='Network • Transmit Packets',
    targets=[query.network_packet_transmit],
    unit='pps',
    description='Network transmit packets per second across all VM interfaces.',
  ),
  networkErrorsReceive: templates.timeSeriesPanel(
    title='Network • Receive Errors',
    targets=[query.network_errors_receive],
    unit='eps',
    description='Inbound packet errors per second.\n\nThese indicate corrupted frames, checksum failures, or driver-level issues.\n\n⚠ Sustained non-zero values are abnormal.\nEven 0.1 errors/sec sustained is worth investigation.',
  ) + {
    fieldConfig+: {
      defaults+: {
        thresholds: {
          mode: 'absolute',
          steps: [
            { color: 'green', value: null },
            { color: 'red', value: 1 },
          ],
        },
        custom: {
          thresholdsStyle: { mode: 'area' },
        },
      },
    },
  },
  networkErrorsTransmit: templates.timeSeriesPanel(
    title='Network • Transmit Errors',
    targets=[query.network_errors_transmit],
    unit='eps',
    description='Outbound packet errors per second.\n\nThese indicate corrupted frames, checksum failures, or driver-level issues.\n\n⚠ Sustained non-zero values are abnormal.\nEven 0.1 errors/sec sustained is worth investigation.',
  ) + {
    fieldConfig+: {
      defaults+: {
        thresholds: {
          mode: 'absolute',
          steps: [
            { color: 'green', value: null },
            { color: 'red', value: 1 },
          ],
        },
        custom: {
          thresholdsStyle: { mode: 'area' },
        },
      },
    },
  },
  networkDropsReceive: templates.timeSeriesPanel(
    title='Network • Receive Drops',
    targets=[query.network_drops_receive],
    unit='dps',
    description='Inbound packets dropped per second.\n\nCommon causes: <br>\n- Buffer exhaustion <br>\n- VM CPU not processing packets fast enough <br>\n- Host networking pressure <br>\n\nDrops + high CPU delay = likely host contention.',
  ),
  networkDropsTransmit: templates.timeSeriesPanel(
    title='Network • Transmit Drops',
    targets=[query.network_drops_transmit],
    unit='dps',
    description='Outbound packets dropped per second.\n\nPotential Causes:\n- Egress shaping\n- Queue limits\n- Host network congestion',
  ),
};

g.dashboard.new('Libvirt Dashboard for Openstack')
+ g.dashboard.withDescription(
  'Comprehensive monitoring for Libvirt virtual machines running on OpenStack. ' +
  'Visualizes CPU, memory, disk I/O, and network traffic per instance. ' +
  'Requires the inovex/prometheus-libvirt-exporter to be installed and scraping metrics.'
)
+ g.dashboard.withTags(['libvirt', 'inovex', 'openstack'])
+ g.dashboard.graphTooltip.withSharedCrosshair()
+ g.dashboard.withVariables([vars.project, vars.vmName, vars.vmId, vars.domId])
+ g.dashboard.withPanels([
  g.panel.row.new('Overview') + { gridPos: { x: 0, y: 0, w: 24, h: 1 } },
  summaryPanels.powerState { gridPos: { x: 0, y: 1, w: 4, h: 4 } },
  summaryPanels.cpuAllocated { gridPos: { x: 4, y: 1, w: 4, h: 4 } },
  summaryPanels.memoryAllocated { gridPos: { x: 8, y: 1, w: 4, h: 4 } },
  summaryPanels.diskCount { gridPos: { x: 12, y: 1, w: 4, h: 4 } },
  summaryPanels.networkPortCount { gridPos: { x: 16, y: 1, w: 4, h: 4 } },

  g.panel.row.new('CPU Information') + { gridPos: { x: 0, y: 2, w: 24, h: 1 } },
  cpuPanel.cpuUsage { gridPos: { x: 0, y: 3, w: 12, h: 10 } },
  cpuPanel.cpuSteal { gridPos: { x: 12, y: 3, w: 12, h: 10 } },

  g.panel.row.new('Memory Information') + { gridPos: { x: 0, y: 4, w: 24, h: 1 } },
  memoryPanel.memoryUsage { gridPos: { x: 0, y: 5, w: 12, h: 10 } },
  memoryPanel.memorySwap { gridPos: { x: 12, y: 5, w: 12, h: 10 } },

  g.panel.row.new('Storage Information') + { gridPos: { x: 0, y: 6, w: 24, h: 1 } },
  storagePanel.iopsTotal { gridPos: { x: 0, y: 7, w: 8, h: 8 } },
  storagePanel.iopsRead { gridPos: { x: 8, y: 7, w: 8, h: 8 } },
  storagePanel.iopsWrite { gridPos: { x: 16, y: 7, w: 8, h: 8 } },
  storagePanel.throughputTotal { gridPos: { x: 0, y: 15, w: 8, h: 8 } },
  storagePanel.throughputRead { gridPos: { x: 8, y: 15, w: 8, h: 8 } },
  storagePanel.throughputWrite { gridPos: { x: 16, y: 15, w: 8, h: 8 } },
  storagePanel.latencyRead { gridPos: { x: 0, y: 23, w: 8, h: 8 } },
  storagePanel.latencyWrite { gridPos: { x: 8, y: 23, w: 8, h: 8 } },
  storagePanel.averageBlockSize { gridPos: { x: 16, y: 23, w: 8, h: 8 } },

  g.panel.row.new('Network Information') + { gridPos: { x: 0, y: 24, w: 24, h: 1 } },
  networkPanel.networkThroughputTotal { gridPos: { x: 0, y: 25, w: 8, h: 8 } },
  networkPanel.networkThroughputReceive { gridPos: { x: 8, y: 25, w: 8, h: 8 } },
  networkPanel.networkThroughputTransmit { gridPos: { x: 16, y: 25, w: 8, h: 8 } },
  networkPanel.networkPacketTotal { gridPos: { x: 0, y: 33, w: 8, h: 8 } },
  networkPanel.networkPacketReceive { gridPos: { x: 8, y: 33, w: 8, h: 8 } },
  networkPanel.networkPacketTransmit { gridPos: { x: 16, y: 33, w: 8, h: 8 } },
  networkPanel.networkErrorsReceive { gridPos: { x: 0, y: 41, w: 12, h: 8 } },
  networkPanel.networkErrorsTransmit { gridPos: { x: 12, y: 41, w: 12, h: 8 } },
  networkPanel.networkDropsReceive { gridPos: { x: 0, y: 49, w: 12, h: 8 } },
  networkPanel.networkDropsTransmit { gridPos: { x: 12, y: 49, w: 12, h: 8 } },

]) + {
  __inputs: [
    {
      name: 'datasource',
      label: 'Prometheus',
      description: 'Select your Prometheus datasource',
      type: 'datasource',
      pluginId: 'prometheus',
      pluginName: 'Prometheus',
    },
  ],
  // Good practice to declare requirements for templates
  __requires: [
    { type: 'grafana', id: 'grafana', name: 'Grafana', version: '9.0.0' },
    { type: 'datasource', id: 'prometheus', name: 'Prometheus', version: '1.0.0' },
  ],
}
