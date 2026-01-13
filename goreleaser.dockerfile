FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/prometheus-libvirt-exporter /prometheus-libvirt-exporter 
ENTRYPOINT ["/prometheus-libvirt-exporter"]