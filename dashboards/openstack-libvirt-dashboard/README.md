# OpenStack Libvirt Dashboard Generation

This directory contains the Jsonnet source code for generating the OpenStack Libvirt Dashboard for Grafana. We use [Jsonnet](https://jsonnet.org/) and the [Grafonnet](https://github.com/grafana/grafonnet) library to define the dashboard as code.

## Prerequisites

To generate the dashboard JSON file, you need to install two tools:

1. **Jsonnet (`jsonnet`)**: The compiler to convert `.jsonnet` files into a `.json` dashboard.
2. **Jsonnet Bundler (`jb`)**: The package manager for Jsonnet to fetch and manage library dependencies like Grafonnet.

### Installation

If you have Go installed on your system, you can easily install both tools using `go install`:

```bash
# Install Jsonnet Bundler (jb)
go install -a github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb@latest

# Install the Go implementation of Jsonnet
go install github.com/google/go-jsonnet/cmd/jsonnet@latest
```

*(Make sure your `$(go env GOPATH)/bin` is in your system's `$PATH` so you can execute the installed binaries).*

## Generating the Dashboard

### 1. Install Dependencies
Before generating the dashboard, you must fetch the required libraries (like Grafonnet) defined in the `jsonnetfile.json`.

```bash
# Make sure you are in the openstack-libvirt-dashboard directory
jb install
```
This command creates a `vendor/` directory containing the downloaded Grafonnet repository.

### 2. Compile Jsonnet to JSON
Once the dependencies are loaded into the `vendor/` directory, you can compile the dashboard by running:

```bash
jsonnet -J vendor main.jsonnet > libvirt-openstack.json
```

This will output the compiled `libvirt-openstack.json` file. You can then copy the contents of this file or directly import it into your Grafana instance.

## Project Structure & Customization

If you want to modify panels, add metrics, or tweak the dashboard layout, here is how the project is structured:

- **`main.jsonnet`**: The primary entry point. This file sets up the dashboard metadata, defines dashboard template variables (like `datasource`, `hypervisor`, `domain`), and organizes the individual panels into rows. If you want to add a new panel or change the layout, you do it here.
- **`lib/query.jsonnet`**: This file contains all the raw Prometheus queries (PromQL) used by the dashboard. The queries are neatly separated from the visual layout. If you need to fix a metric formula or adjust how PromQL calculates CPU/Memory/Storage/Network, modify this file.
- **`jsonnetfile.json`**: Controls the upstream dependencies and their specific versions.

### Workflow for Customizing
1. Identify what you want to change: Layout panels (`main.jsonnet`) or PromQL data calculations (`lib/query.jsonnet`).
2. Make your edits.
3. Run `jsonnet -J vendor main.jsonnet > libvirt-openstack.json` to generate your updated JSON structure.
4. Import the new `libvirt-openstack.json` into Grafana to test your changes.
