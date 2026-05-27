VES_PASS=0
VES_FAIL=0
VES_STEP=1

# Load configuration. Always load the conf shipped next to this include
# first; then layer ~/.vestest.conf on top if present so user-specific
# overrides (e.g. EMAIL/EMAIL2) take effect without editing the tree.
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/vestest.conf"
[ -f "$HOME/.vestest.conf" ] && . "$HOME/.vestest.conf"

vestest() {
    local ECODE CMD RSLT RCODE OK EXP
    ECODE=$1
    shift
    CMD="$VES ${@@Q}"
    echo -n '[1;30m'
    RSLT=`$VES "$@"`
    RCODE=$?
    echo -n '[0m'
    OK=0
    if [ "$ECODE" == "-" ]
    then
        EXP=`cat`
        [ "$RCODE" == "0" -a "$EXP" == "$RSLT" ] && OK=1
    else
        [ "$RCODE" == "$ECODE" ] && OK=1
    fi
    ((VES_STEP++))
    if [ $OK == "1" ]
    then
        echo '[[1;32mPASSED[0m]'"($RCODE)" "$CMD"
        ((++VES_PASS))
    else
        echo '[[1;31mFAILED[0m]'"($RCODE)" "$CMD"
        ((++VES_FAIL))
        echo
        echo "$RSLT"
        echo
        return $RCODE
    fi
}

vestest_head() {
    echo
    echo '[1;33m'"$@"'[0m'
}

vestest_init() {
    local ACCT
    ACCT=$1
    $VES -a //$DOM/$ACCT/ > /dev/null
    if [ $? -eq 7 ]
    then
        vestest_head Creating an app vault for $ACCT, VES PIN entry expected
        vestest 0 -A $ACCT -a //$DOM/$ACCT/ -n -E primary,elevate,save || exit 1
    fi
}

vestest_admin_init() {
    local ACCT
    ACCT=$1
    $VES -a //.admin/$ACCT/ > /dev/null 2>&1
    if [ $? -eq 7 ]
    then
        vestest_head Creating an .admin vault for $ACCT, VES PIN entry expected
        vestest 0 -A $ACCT -a //.admin/$ACCT/ -n -E primary,elevate,save || exit 1
    fi
}

vestest_stats() {
    echo
    echo '[1;96mPassed: '"$VES_PASS"'[0m'
    echo '[1;96mFailed: '"$VES_FAIL"'[0m'
}

trap vestest_stats EXIT
