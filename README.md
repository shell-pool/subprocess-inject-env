# subprocess-inject-env

This crate provides a mechanism to tweak environment variables
within a child subprocess dynamically without the subprocess
needing to know anything about it. To do this, we build a
.so file that registers a startup hook and launches a background
thread listening on a control unix socket. The parent process
can then dial in to the control socket, authenticate, and
then place an RPC call to setenv. Since the syscall is invoked
in the ~victim~ child process, the child's environment changes
on the fly.

This crate was developed in service of the `shpool` tool, but
it is a general tool so it is split out into its own crate.

subprocess-inject-env is known to work on linux.
