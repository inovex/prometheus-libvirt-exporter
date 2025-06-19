package main

import (
	"fmt"
	"net/http"
	"os"

	kingpin "github.com/alecthomas/kingpin/v2"
	"github.com/digitalocean/go-libvirt"
	exporter "github.com/inovex/prometheus-libvirt-exporter/pkg/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	prometheus_version "github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
)

var version string

func main() {

	prometheus_version.Version = version

	var (
		libvirtURI = kingpin.Flag("libvirt.uri",
			"Libvirt URI from which to extract metrics.",
		).Default("/var/run/libvirt/libvirt-sock-ro").String()
		driver = kingpin.Flag("libvirt.driver",
			fmt.Sprintf("Available drivers: %s (Default), %s, %s and %s ", libvirt.QEMUSystem, libvirt.QEMUSession, libvirt.XenSystem, libvirt.TestDefault),
		).Default(string(libvirt.QEMUSystem)).String()
		timeout = kingpin.Flag("exporter.timeout",
			"Maximum libvirt API call duration.",
		).Default("3s").Duration()
		maxConcurrentCollects = kingpin.Flag("exporter.max-concurrent-collects",
			"Maximum number of concurrent collects (min: 1).",
		).Default("4").Int()
	)

	metricsPath := kingpin.Flag(
		"web.telemetry-path", "Path under which to expose metrics",
	).Default("/metrics").String()
	toolkitFlags := webflag.AddFlags(kingpin.CommandLine, ":9177")

	promlogConfig := &promslog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(prometheus_version.Print("libvirt_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promslog.New(promlogConfig)

	// ensure maxConcurrentCollects is not less than 1
	if *maxConcurrentCollects < 1 {
		logger.Info("max-concurrent-collects must be at least 1, setting to 1")
		*maxConcurrentCollects = 1
	}

	logger.Info("Starting libvirt_exporter", "version", prometheus_version.Info())
	logger.Info("Build context", "build_context", prometheus_version.BuildContext())
	logger.Info("Timeout value", "timeout_value", *timeout)
	logger.Info("Max concurrent collects", "max_concurrent_collects", *maxConcurrentCollects)

	exporter, err := exporter.NewLibvirtExporter(*libvirtURI, libvirt.ConnectURI(*driver), logger, *timeout, *maxConcurrentCollects)
	if err != nil {
		panic(err)
	}
	prometheus.MustRegister(exporter)

	http.Handle(*metricsPath, promhttp.Handler())
	if *metricsPath != "/" {
		landingCnf := web.LandingConfig{
			Name:        "Libvirt Exporter",
			Description: "Prometheus Libvirt Exporter",
			Version:     prometheus_version.Info(),
			Links: []web.LandingLinks{
				{
					Address: *metricsPath,
					Text:    "Metrics",
				},
			},
		}
		landingPage, err := web.NewLandingPage(landingCnf)
		if err != nil {
			logger.Error("Failed to generate landing page", "msg", err)
			os.Exit(1)
		}
		http.Handle("/", landingPage)
	}

	srv := &http.Server{}
	if err = web.ListenAndServe(srv, toolkitFlags, logger); err != nil {
		logger.Error("Failed to start server", "msg", err)
		os.Exit(1)
	}
}
