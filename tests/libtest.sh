################################################################################
# Set a trap while maintaining the one currently set. The new one will be
# executed first.
# Arguments:
#   $1 -> new command to execute during the trap
#   $2 -> signal to trap
################################################################################
function cumulative_trap()
{
	local new_command="$1"
	local signal="$2"
	local current_command=""

	# If we run "trap -p SIGNAL" in a subshell we read the traps for that
	# subshell, instead of the current one.
	# https://unix.stackexchange.com/a/334593
	shopt -s lastpipe
	trap -p "$signal" | read current_command
	shopt -u lastpipe

	current_command="$(echo $current_command | awk -F\' '{print $2}')"
	new_command="$new_command; $current_command"
	trap "$new_command" "$signal"
}

################################################################################
# Create a pair of veth devices.
# Arguments:
#   $1 -> base name for the veth
################################################################################
function create_veth_pair()
{
    local ifname="$1"

    ip link add ${ifname}0 type veth peer name ${ifname}1 || return 1
    cumulative_trap "ip link del ${ifname}0" "EXIT"
    ip link set ${ifname}0 up || return 1
    ip link set ${ifname}1 up || return 1
}
