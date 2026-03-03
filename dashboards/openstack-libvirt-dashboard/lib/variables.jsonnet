local g = import 'github.com/grafana/grafonnet/gen/grafonnet-v11.4.0/main.libsonnet';

{
  //   datasource:
  //     g.dashboard.variable.datasource.new('datasource', 'prometheus')
  //     + g.dashboard.variable.datasource.generalOptions.withLabel('DataSource'),

  project:
    g.dashboard.variable.query.new('project_name', 'label_values(libvirt_domain_openstack_info, project_name)')
    + g.dashboard.variable.query.withDatasource('prometheus', '${datasource}')
    + g.dashboard.variable.query.refresh.onLoad()
    + g.dashboard.variable.query.generalOptions.withLabel('Project Name'),

  vmName:
    g.dashboard.variable.query.new('vm_name', 'label_values(libvirt_domain_openstack_info{project_name="$project_name"}, instance_name)')
    + g.dashboard.variable.query.withDatasource('prometheus', '${datasource}')
    + g.dashboard.variable.query.refresh.onLoad()
    + g.dashboard.variable.query.generalOptions.withLabel('VM Name'),

  vmId:
    g.dashboard.variable.query.new('vm_id', 'label_values(libvirt_domain_openstack_info{instance_name="$vm_name", project_name="$project_name"}, instance_id)')
    + g.dashboard.variable.query.withDatasource('prometheus', '${datasource}')
    + g.dashboard.variable.query.refresh.onLoad()
    + g.dashboard.variable.query.generalOptions.withLabel('VM ID'),

  domId:
    g.dashboard.variable.query.new('dom_id', 'label_values(libvirt_domain_openstack_info{instance_name="$vm_name", project_name="$project_name", instance_id="$vm_id"},domain)')
    + g.dashboard.variable.query.withDatasource('prometheus', '${datasource}')
    + g.dashboard.variable.query.refresh.onLoad()
    + g.dashboard.variable.query.generalOptions.withLabel('Domain ID') + { hide: 2 },
}
