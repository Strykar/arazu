# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# Run user-context tools from a root script.
#
# THE CLASS, not the instance. minikube, kubectl, helm and the Go build cache
# all key off the LOGIN USER's home: minikube keeps its profile there, kubectl
# its kubeconfig, go its cache. A root script that calls them directly gets
# "Profile not found" or an empty context on a perfectly healthy cluster, and
# then reports that as the thing it was testing.
#
# This has now been fixed three times in three places — test-noroute.sh open-
# coded it, r14-routing-test.sh open-coded it again, and r14-probe.sh did not
# have it at all and blamed the exposure for a root-context failure. The fix
# kept attaching to the file being edited rather than to the class it belongs
# to. This file is where it lives now; source it instead of rewriting it.
#
# Usage:  . "$(dirname "$0")/lib/as-user.sh"
#         as_user minikube status
#         as_user kubectl get pods -n crs
RUN_AS="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
RUN_AS_HOME="$(eval echo ~"$RUN_AS")"

as_user() {
    if [ "$RUN_AS" = root ]; then
        env HOME="$RUN_AS_HOME" "$@"
    else
        sudo -u "$RUN_AS" env HOME="$RUN_AS_HOME" PATH="$PATH" "$@"
    fi
}
