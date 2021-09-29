tcp-audit-bpf-eventer
=====================

This module implements a `tcp-audit` Eventer plugin which sources TCP state change events from the kernel tracepoints via a BPF program loaded into the kernel.

The BPF program uses [BPF CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re) in order to read kernel structures and hence requires a kernel which exposes [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) information. The presence of the `/sys/kernel/btf/vmlinux` file indicates that BTF information is present and that this Eventer is supported.

The user-space portion of the Eventer uses [libbpf](https://github.com/libbpf/libbpf#readme) to load the BPF program into the kernel and communicate with it after it is loaded. This requires that the tracefs filesystem is mounted at the `/sys/kernel/debug/tracing` mountpoint. Because of this requirement, when running tcp-audit in a container, the host's debugfs must be mounted into the container at `/sys/kernel/debug/`. For example, for Docker, the `--volume /sys/kernel/debug:/sys/kernel/debug` argument would be required to `docker run`. (For a detailed explanation of why the entire debugfs and not just tracefs must be mounted into the container, see below).

Extra permissions and capabilities
----------------------------------

When using this Eventer, tcp-audit requires the capability to insert BPF programs into the kernel. If the container runtime does not grant this privilege to containers by default (e.g. Docker), it must be added. For Docker this would mean passing the `--cap-add SYS_ADMIN` argument to `docker run`. (In kernels >=5.8, `CAP_BPF` should be able to be used, but this is not currently supported by Docker - see `man 7 capabilities`).

The container must run as UID 0 (`root`) as this is the owner of the pseudo-files exposed by the tracefs filesystem. (For details on running as non-root, see below).

Running as non-root
-------------------

Running within a container as non-root requires a few extra steps:
- Ensuring that tcp-audit process is run with the `CAP_DAC_OVERRIDE` capability. This is required as the pseudo-files exposed by tracefs are owned by (and readable only by) root, and hence to read them the user must either be root or have the capability to override the ownership permission checks.
- Ensuring the that tcp-audit process is running with the `CAP_SYS_ADMIN` capability.

These require passing the `--cap-add SYS_ADMIN` and `--cap-add DAC_OVERRIDE` arguments to `docker run`, but this in itself is not sufficient. In addition, the tcp-audit file must have these same capabilities set into the file permitted set, and the effective bit turned on. This ensures that the tcp-audit process is executed with these capabilities.

Note that the effective bit is set on the file as tcp-audit is currently "capability dumb". From `man 7 capabilities`:

```
A capability-dumb binary is an application that has been marked to have
file capabilities, but has not been converted to use the libcap(3)  API
to manipulate its capabilities.  (In other words, this is a traditional
set-user-ID-root program that has been switched to use  file  capabili‐
ties, but whose code has not been modified to understand capabilities.)
For such applications, the effective capability bit is set on the file,
so  that  the  file permitted capabilities are automatically enabled in
the process effective set when executing the file.  The  kernel  recog‐
nizes  a file which has the effective capability bit set as capability-
dumb for the purpose of the check described here.
```

Working example Dockerfile
--------------------------

Bringing the above discussions together, the following Dockerfile will create a runnable complete tcp-audit system using the BPF Eventer and the PostgresSQL sink plugins:

```Dockerfile
FROM tcpaudit:latest
COPY --from=tcpauditbpfeventer:latest --chown=nonroot:nonroot \
     /tmp/tcp-audit-bpf-eventer.so \     
     /tmp/libelf.so.1 \
     /tmp/libelf-0.183.so \
     /tmp/libz.so.1.2.11 \
     /tmp/libz.so.1 \
     /lib/
COPY --from=tcpauditpgsqlsink:latest --chown=nonroot:nonroot /tmp/tcp-audit-pgsql-sink.so /lib/tcp-audit-pgsql-sink.so
COPY --from=wildwildangel/setcap-static /setcap-static /!setcap-static
USER root:root
RUN ["/!setcap-static", "cap_sys_admin,cap_dac_override=+ep", "/usr/bin/tcp-audit"]
USER nonroot:nonroot
ENTRYPOINT [ "/usr/bin/tcp-audit", "--event", "/lib/tcp-audit-bpf-eventer.so", "--sink", "/lib/tcp-audit-pgsql-sink.so" ]
```

Note that this Dockerfile makes use of the `wildwildangel/setcap-static` image in order to set the tcp-audit file capabilities in a distroless image. For more discussion on this, see the [author's blog post](https://wildwolf.name/multi-stage-docker-builds-and-xattrs/).

The above Dockerfile, once tagged as `tcpauditcomplete:latest`, can be run with something like:

```
docker run -ti --cap-drop all --cap-add SYS_ADMIN --cap-add DAC_OVERRIDE --volume /sys/kernel/debug:/sys/kernel/debug --env PGHOST=172.17.0.2 --env PGDATABASE=postgres --env PGPASSWORD=password  --env PGUSER=postgres tcpauditcomplete:latest
```

Why must debugfs be mounted into the container, and not just tracefs?
---------------------------------------------------------------------

libbpf appears to be [hardcoded](https://github.com/libbpf/libbpf/blob/ebf17ac6288e668b5e5999b74c970498ad311bd2/src/libbpf.c#L9709) to look only for `/sys/kernel/debug/tracing` when attaching a BPF program to a kernel tracepoint and will fail if only `/sys/kernel/tracing` (the other tracefs mountpoint) is mounted.

However, it is not possible to mount `/sys/kernel/debug/tracing` (nor `/sys/kernel/tracing`) to `/sys/kernel/debug/tracing` within the container filesystem, as `/sys/kernel/debug/tracing` directory does not exist until it is first accessed. As it does not exist, it cannot be a mountpoint.

In contrast, `/sys/kernel/tracing` does exist as an empty directory in the container's sysfs (it is *not* created on demand), so can be a mountpoint. Unfortunately, as libbpf appears not to support this path, this is of no use to us.

Creating a `/sys/kernel/debug/tracing` directory (e.g. with `mkdir`) ahead-of-time to use as a mountpoint at runtime (i.e. in the image) to use as a mountpoint fails with `No such file or directory`, presumably due to the read-only nature of sysfs.

A hack such as `COPY --from=builder /tmp/tracing /sys/kernel/debug/tracing` to create at directory works when building the image (no error),
but the auto-mount of sysfs at `/sys` in the container hides this directory at runtime.

So the fact that `/sys/kernel/debug/tracing` does not exist until it is accessed leaves only one option: Mount the whole debugfs from the host onto `/sys/kernel/debug`, which will cause tracefs to auto-mount at `/sys/kernel/debug/tracing` when accessed by libbpf.
