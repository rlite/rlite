################################################################################
# Set a trap while maintaining the one currently set. The new one will be
# executed first.
# Arguments:
#   $1 -> new command to execute during the trap
#   $2 -> signal to trap
################################################################################
function cumulative_trap()
{
    local new_commands="$1"
    local signal="$2"
    local current_commands=""

    # If we run "trap -p SIGNAL" in a subshell we read the traps for that
    # subshell, instead of the current one.
    # https://unix.stackexchange.com/a/334593
    shopt -s lastpipe
    trap -p "$signal" | read current_commands || true
    shopt -u lastpipe
    current_commands="$(echo $current_commands | awk -F\' '{print $2}')"
    new_commands="$new_commands; $current_commands"

    trap "$new_commands" "$signal"
}

################################################################################
# Create a pair of veth devices.
# Arguments:
#   $1 -> base name for the veth
#   $2 -> name extension for the first peer (optional, default="0")
#   $3 -> name extension for the sedcond peer (optional, default="1")
################################################################################
function create_veth_pair()
{
    local ifname="$1"
    local sx="${2:-0}"
    local dx="${3:-1}"

    ip link add ${ifname}.${sx} type veth peer name ${ifname}.${dx} || return 1
    cumulative_trap "ip link del ${ifname}.${sx} || true" "EXIT"
    ip link set ${ifname}.${sx} up || return 1
    ip link set ${ifname}.${dx} up || return 1
}

################################################################################
# Create a bridge.
# Arguments:
#   $1 -> bridge name
################################################################################
function create_bridge()
{
    local brname="$1"

    ip link add name ${brname} type bridge || return 1
    cumulative_trap "ip link del ${brname} type bridge || true" "EXIT"
    ip link set ${brname} up || return 1
}

################################################################################
# Create a network namespace.
# Arguments:
#   $1 -> name of the namespace
################################################################################
function create_namespace()
{
    local name="$1"

    ip netns add ${name} || return 1
    cumulative_trap "ip netns delete ${name}" "EXIT"
    ip netns exec ${name} ip link set lo up || return 1
    ip netns exec ${name} rlite-uipcps -d || return 1
    cumulative_trap "ip netns exec ${name} rlite-ctl terminate || true" "EXIT"
    cumulative_trap "ip netns exec ${name} rlite-ctl reset || true" "EXIT"
    # veths are autodeleted once the namespace is deleted
}

################################################################################
# Start a daemon process.
# Arguments:
#   $1 -> daemon name
#   $2 -> daemon arguments
################################################################################
function start_daemon()
{
    local progname="$1"
    shift
    $progname $@ || return 1
    cumulative_trap "pkill $progname || true" "EXIT"
}

################################################################################
# Start a daemon process in a network namespace.
# Arguments:
#   $1 -> namespace name
#   $2 -> daemon name
#   $3 -> daemon arguments
################################################################################
function start_daemon_namespace()
{
    local namespace="$1"
    local progname="$2"
    shift
    shift
    ip netns exec "${namespace}" ${progname} $@ || return 1
    cumulative_trap "ip netns exec ${namespace} pkill ${progname} || true" "EXIT"
}
