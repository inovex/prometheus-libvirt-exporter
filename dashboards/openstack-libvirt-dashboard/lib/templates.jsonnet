local g = import 'github.com/grafana/grafonnet/gen/grafonnet-v11.4.0/main.libsonnet';

{
  // A specialized Stat panel for this specific dashboard context
  vmStatPanel(title, targets, description='', unit=null, colorMode='value', mappings=[], noThresholds=false)::
    local base = g.panel.stat.new(title)
                 + g.panel.stat.queryOptions.withDatasource('prometheus', '${datasource}')
                 + g.panel.stat.queryOptions.withTargets(targets)
                 + g.panel.stat.options.withGraphMode('area')
                 + g.panel.stat.options.reduceOptions.withCalcs(['lastNotNull'])
                 + g.panel.stat.standardOptions.withNoValue('Requires VM to be powered-on');

    // Manual Field Config for Thresholds
    local thresholdConfig = if noThresholds then
      {
        fieldConfig: {
          defaults: {
            thresholds: {
              mode: 'absolute',
              // A single step with null value = solid color everywhere
              steps: [{ color: 'green', value: 0 }],
            },
          },
        },
      }
    else
      {};

    base
    + g.panel.stat.options.withColorMode(colorMode)
    + thresholdConfig  // Apply the manual config here
    + (if description != '' then g.panel.stat.panelOptions.withDescription(description) else {})
    + (if unit != null then g.panel.stat.standardOptions.withUnit(unit) else {})
    + (if std.length(mappings) > 0 then g.panel.stat.standardOptions.withMappings(mappings) else {}),


  timeSeriesPanel(title, targets, unit=null, description='', noThresholds=false)::
    g.panel.timeSeries.new(title)
    + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${datasource}')
    + g.panel.timeSeries.queryOptions.withTargets(targets)
    + g.panel.timeSeries.options.legend.withDisplayMode('list')
    + g.panel.timeSeries.options.legend.withPlacement('bottom')
    + g.panel.timeSeries.options.tooltip.withMode('multi')
    + g.panel.timeSeries.standardOptions.withNoValue('No Data')
    + (if unit != null then g.panel.timeSeries.standardOptions.withUnit(unit) else {})
    + (if description != '' then g.panel.timeSeries.panelOptions.withDescription(description) else {}),
}
