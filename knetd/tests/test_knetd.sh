#!/bin/bash
#
# Integration test suite for knetd and knetctl.
#
# Tests all RPC commands exercised through knetctl against a live knetd daemon
# started with a temporary socket. No root required (non-privileged mode).
#
# Usage (direct):
#   KNETD_BIN=/path/to/knetd KNETCTL_BIN=/path/to/knetctl ./test_knetd.sh
#
# Usage (via make check):
#   make check   (Makefile passes KNETD_BIN and KNETCTL_BIN automatically)
#
# Exit codes:
#   0  - all tests passed
#   1  - one or more tests failed
#   77 - skip (binaries not found; automake interprets this as SKIP)
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Binary locations: env vars > positional args > auto-detect from build tree
KNETD="${KNETD_BIN:-${1:-${SCRIPT_DIR}/../target/release/knetd}}"
KNETCTL="${KNETCTL_BIN:-${2:-${SCRIPT_DIR}/../target/release/knetctl}}"

PASS=0
FAIL=0

# ============================================================================
# Temporary working directory and cleanup
# ============================================================================

TESTDIR=$(mktemp -d /tmp/knetd-test.XXXXXX)
SOCKET="${TESTDIR}/knetd.sock"
KNETD_PID=0

cleanup() {
	if [ $KNETD_PID -ne 0 ]; then
		kill "$KNETD_PID" 2>/dev/null
		wait "$KNETD_PID" 2>/dev/null
	fi
	rm -rf "$TESTDIR"
}
trap cleanup EXIT INT TERM

# ============================================================================
# Test helper functions
# ============================================================================

pass() {
	printf "PASS: %s\n" "$1"
	PASS=$((PASS + 1))
}

fail() {
	printf "FAIL: %s\n" "$1"
	[ -n "$2" ] && printf "      %s\n" "$2"
	FAIL=$((FAIL + 1))
}

# Run knetctl and expect success (exit 0).
# Prints the command output and returns it via $CTL_OUTPUT.
CTL_OUTPUT=""
ctl_ok() {
	local test_name="$1"
	shift
	CTL_OUTPUT=$("$KNETCTL" -s "$SOCKET" "$@" 2>&1)
	local rc=$?
	if [ $rc -eq 0 ]; then
		pass "$test_name"
	else
		fail "$test_name" "rc=$rc  output: $CTL_OUTPUT"
	fi
}

# Run knetctl and expect failure (non-zero exit).
ctl_fail() {
	local test_name="$1"
	shift
	local out
	out=$("$KNETCTL" -s "$SOCKET" "$@" 2>&1)
	local rc=$?
	if [ $rc -ne 0 ]; then
		pass "$test_name"
	else
		fail "$test_name" "expected failure but succeeded: $out"
	fi
}

# Assert that $CTL_OUTPUT contains a substring.
contains() {
	local test_name="$1"
	local needle="$2"
	if echo "$CTL_OUTPUT" | grep -qF "$needle"; then
		pass "$test_name"
	else
		fail "$test_name" "expected '$needle' in: $CTL_OUTPUT"
	fi
}

# Assert that $CTL_OUTPUT does NOT contain a substring.
not_contains() {
	local test_name="$1"
	local needle="$2"
	if echo "$CTL_OUTPUT" | grep -qF "$needle"; then
		fail "$test_name" "unexpected '$needle' in: $CTL_OUTPUT"
	else
		pass "$test_name"
	fi
}

# ============================================================================
# Pre-flight: verify binaries exist
# ============================================================================

if [ ! -x "$KNETD" ]; then
	echo "SKIP: knetd binary not found at $KNETD"
	exit 77
fi
if [ ! -x "$KNETCTL" ]; then
	echo "SKIP: knetctl binary not found at $KNETCTL"
	exit 77
fi

printf "knetd:   %s\n" "$KNETD"
printf "knetctl: %s\n" "$KNETCTL"
echo ""

# ============================================================================
# Start the daemon with a temporary socket
# ============================================================================

MY_UID=$(id -u)

cat > "${TESTDIR}/knetd.toml" <<EOF
socket_path = "${SOCKET}"
log_level   = "error"
disable_privileged = true
allowed_users = ["${MY_UID}"]
EOF

"$KNETD" -c "${TESTDIR}/knetd.toml" > "${TESTDIR}/knetd.log" 2>&1 &
KNETD_PID=$!

# Wait up to 5 s for the socket to appear
WAITED=0
while [ ! -S "$SOCKET" ] && [ $WAITED -lt 50 ]; do
	sleep 0.1
	WAITED=$((WAITED + 1))
done

if [ ! -S "$SOCKET" ]; then
	echo "FAIL: knetd did not create socket within 5 seconds"
	cat "${TESTDIR}/knetd.log"
	exit 1
fi

printf "knetd started (PID %d)\n\n" "$KNETD_PID"

# ============================================================================
# Section 1: Daemon connectivity
# ============================================================================
echo "=== 1. Connectivity ==="

ctl_ok   "ping daemon"                   ping
contains "ping response contains 'pong'" "pong"

ctl_fail "ping wrong socket path" -s "/tmp/knetd-nonexistent-$$.sock" ping

echo ""

# ============================================================================
# Section 2: Instance lifecycle
# ============================================================================
echo "=== 2. Instance lifecycle ==="

# Create first instance
ctl_ok   "instance create test1"              instance create -n test1 -H 1
contains "create test1: success message"      "Created instance"

# List shows the new instance
ctl_ok   "instance list after create"         instance list
contains "list: test1 present"                "test1"
contains "list: initial state is STOPPED"     "STOPPED"

# Duplicate name must be rejected
ctl_fail "instance create duplicate name"     instance create -n test1 -H 2

# Create second instance with different host id
ctl_ok   "instance create test2"              instance create -n test2 -H 3
ctl_ok   "instance list shows both"           instance list
contains "list: test2 present"                "test2"

# Start (enable forwarding)
ctl_ok   "instance start test1"               instance start -n test1
contains "start: success message"             "Started instance"

ctl_ok   "instance list after start"          instance list
contains "list: test1 now RUNNING"            "RUNNING"

# Stop (disable forwarding)
ctl_ok   "instance stop test1"                instance stop -n test1
contains "stop: success message"              "Stopped instance"

ctl_ok   "instance list after stop"           instance list
contains "list: test1 back to STOPPED"        "STOPPED"

# Error: operate on nonexistent instance
ctl_fail "instance start nonexistent"         instance start -n noexist
ctl_fail "instance stop nonexistent"          instance stop -n noexist

echo ""

# ============================================================================
# Section 3: Host management
# ============================================================================
echo "=== 3. Host management ==="

# Add a host without a name
ctl_ok   "host add (no name)"                 host add -i test1 -H 2
contains "host add: success message"          "Added host"

# Add a host with a name
ctl_ok   "host add with name"                 host add -i test1 -H 4 -n node4
contains "host add name: success"             "Added host"

# List hosts
ctl_ok   "host list"                          host list -i test1
contains "host list: host 2 present"          "2"
contains "host list: host 4 present"          "4"
contains "host list: name 'node4' present"    "node4"

# Per-host status
ctl_ok   "host status for host 2"             host status -i test1 -H 2
contains "host status: shows host id"         "2"

ctl_ok   "host status for named host 4"       host status -i test1 -H 4
contains "host status: shows name"            "node4"

# Error: host operations on nonexistent instance
ctl_fail "host add to nonexistent instance"   host add -i noexist -H 5
ctl_fail "host status nonexistent instance"   host status -i noexist -H 2

# Error: status for a host that was never added
ctl_fail "host status for unknown host id"    host status -i test1 -H 99

# Remove one host
ctl_ok   "host remove host 4"                 host remove -i test1 -H 4
contains "host remove: success"               "Removed host"

# Verify host 4 is gone, host 2 remains
ctl_ok   "host list after remove"             host list -i test1
contains "host 2 still listed"                "2"
not_contains "host 4 no longer listed"        "node4"

# Error: remove already-removed host
ctl_fail "host remove again (should fail)"    host remove -i test1 -H 4

echo ""

# ============================================================================
# Section 4: Link management
# ============================================================================
echo "=== 4. Link management ==="

# Pick random high-numbered ports to minimise collision chance
SRC_PORT=$((RANDOM % 10000 + 50000))
DST_PORT=$((RANDOM % 10000 + 40000))

ctl_ok   "link config (UDP loopback)"         \
         link config -i test1 -H 2 -l 0       \
         -t udp                                \
         -s "127.0.0.1:${SRC_PORT}"           \
         -d "127.0.0.1:${DST_PORT}"
contains "link config: success"               "Configured link"

# Enable the link
ctl_ok   "link enable"                        link enable  -i test1 -H 2 -l 0
contains "link enable: success"               "Enabled link"

# Status
ctl_ok   "link status"                        link status  -i test1 -H 2 -l 0
contains "link status: shows Enabled=yes"     "yes"

# Statistics (counters start at zero but the fields must appear)
ctl_ok   "link stats"                         link stats   -i test1 -H 2 -l 0
contains "link stats: TX field"               "TX"
contains "link stats: RX field"               "RX"
contains "link stats: Latency field"          "Latency"

# Disable the link
ctl_ok   "link disable"                       link disable -i test1 -H 2 -l 0
contains "link disable: success"              "Disabled link"

# Verify disabled
ctl_ok   "link status after disable"          link status  -i test1 -H 2 -l 0
contains "link now shows disabled"            "no"

# Error cases
ctl_fail "link config nonexistent instance"   \
         link config -i noexist -H 2 -l 0    \
         -s "127.0.0.1:25200" -d "127.0.0.1:25201"
ctl_fail "link enable nonexistent instance"   link enable  -i noexist -H 2 -l 0
ctl_fail "link status nonexistent instance"   link status  -i noexist -H 2 -l 0
ctl_fail "link stats nonexistent instance"    link stats   -i noexist -H 2 -l 0

echo ""

# ============================================================================
# Section 5: Event subscription
# ============================================================================
echo "=== 5. Events ==="

# The 'events watch' command loops forever; run it briefly and capture its
# startup output to verify the subscription was accepted.
EVENTS_OUT="${TESTDIR}/events.out"

timeout 2 "$KNETCTL" -s "$SOCKET" events watch -i test1 \
	> "$EVENTS_OUT" 2>&1 &
WATCH_PID=$!
sleep 0.5
kill "$WATCH_PID" 2>/dev/null
wait "$WATCH_PID" 2>/dev/null || true

CTL_OUTPUT=$(cat "$EVENTS_OUT")
contains "events watch: subscribed message"   "Subscribed"

# Nonexistent instance must fail to subscribe
timeout 2 "$KNETCTL" -s "$SOCKET" events watch -i noexist \
	> "${TESTDIR}/events_err.out" 2>&1 &
WATCH_ERR_PID=$!
sleep 0.5
kill "$WATCH_ERR_PID" 2>/dev/null
wait "$WATCH_ERR_PID" 2>/dev/null || true

# On failure the knetctl process exits non-zero and prints an error
WATCH_ERR_OUT=$(cat "${TESTDIR}/events_err.out")
if echo "$WATCH_ERR_OUT" | grep -qiE "(not found|error|Error|failed)"; then
	pass "events watch: nonexistent instance rejected"
else
	fail "events watch: nonexistent instance rejected" \
	     "output was: $WATCH_ERR_OUT"
fi

echo ""

# ============================================================================
# Section 6: Compression
# ============================================================================
echo "=== 6. Compression ==="

ctl_ok   "compress set-config (lz4)"          \
         compress set-config -i test1 -m lz4 -t 100 -l 1
contains "compress: success message"          "Compression configuration set"

# Verify the setting appears in the instance list
ctl_ok   "instance list shows compression"    instance list
contains "list: compression model present"    "lz4"

ctl_fail "compress on nonexistent instance"   compress set-config -i noexist -m lz4

echo ""

# ============================================================================
# Section 7: Cryptography
# ============================================================================
echo "=== 7. Cryptography ==="

KEY_FILE="${TESTDIR}/crypto.key"
dd if=/dev/urandom of="$KEY_FILE" bs=1024 count=2 2>/dev/null

ctl_ok   "crypto set-config (openssl/aes256/sha256)" \
         crypto set-config                           \
         -i test1 -m openssl -c aes256 -H sha256    \
         -k "$KEY_FILE" -n 1
contains "crypto: success message"            "Crypto configuration set"

# Verify the setting appears in the instance list
ctl_ok   "instance list shows crypto"         instance list
contains "list: crypto model present"         "openssl"

# Key file smaller than 1024 bytes must be rejected client-side
SMALL_KEY="${TESTDIR}/small.key"
dd if=/dev/urandom of="$SMALL_KEY" bs=512 count=1 2>/dev/null

SMALL_OUT=$("$KNETCTL" -s "$SOCKET" crypto set-config \
	-i test1 -m openssl -c aes256 -H sha256           \
	-k "$SMALL_KEY" 2>&1 || true)
if echo "$SMALL_OUT" | grep -qiE "(1024|too small|key)"; then
	pass "crypto: small key rejected"
else
	fail "crypto: small key rejected" "output: $SMALL_OUT"
fi

ctl_fail "crypto on nonexistent instance"     \
         crypto set-config -i noexist         \
         -m openssl -c aes256 -H sha256 -k "$KEY_FILE"

echo ""

# ============================================================================
# Section 8: Topology
# ============================================================================
echo "=== 8. Topology ==="

# Plain ASCII display
ctl_ok   "topology show"                      topology show -i test1
contains "topology: instance name present"    "test1"

# DOT export
DOT_FILE="${TESTDIR}/topology.dot"
ctl_ok   "topology export (dot)"              \
         topology export -i test1 -f dot -o "$DOT_FILE"
if [ -s "$DOT_FILE" ]; then
	pass "topology: dot file created"
else
	fail "topology: dot file created" "file is empty or missing"
fi

ctl_fail "topology nonexistent instance"      topology show -i noexist

echo ""

# ============================================================================
# Section 9: Instance teardown
# ============================================================================
echo "=== 9. Instance teardown ==="

ctl_ok   "instance destroy test2"             instance destroy -n test2
contains "destroy test2: success"             "Destroyed instance"

ctl_fail "instance destroy nonexistent"       instance destroy -n noexist
ctl_fail "instance destroy already-gone"      instance destroy -n test2

ctl_ok   "instance destroy test1"             instance destroy -n test1
contains "destroy test1: success"             "Destroyed instance"

ctl_ok   "instance list is now empty"         instance list
contains "empty list message"                 "No instances"

echo ""

# ============================================================================
# Summary
# ============================================================================
echo "=== Summary ==="
printf "Passed: %d\n" "$PASS"
printf "Failed: %d\n" "$FAIL"
echo ""

if [ $FAIL -gt 0 ]; then
	echo "RESULT: FAILED"
	exit 1
else
	echo "RESULT: ALL TESTS PASSED"
	exit 0
fi
