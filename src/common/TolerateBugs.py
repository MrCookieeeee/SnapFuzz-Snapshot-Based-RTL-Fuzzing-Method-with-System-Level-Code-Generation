# This utility defines which workaround should be disabled.
# This allows, for example, to measure time to bug detection.
# Some bugs must be reintroduced in hw and cannot simply be reintroduced as a non-workaround in the fuzzer.

###
# If this is True ,i dont think we need to turn off xiangshan
###

__NO_INTERACTION_MINSTRET = True
def is_no_interaction_minstret(design_name):
    return __NO_INTERACTION_MINSTRET

###
# BOOM
###

__TOLERATE_BOOM_MINSTRET = True
def is_tolerate_boom_minstret():
    return __TOLERATE_BOOM_MINSTRET
if __TOLERATE_BOOM_MINSTRET:
    print('WARNING: Tolerating one bug: __TOLERATE_BOOM_MINSTRET')

###
# Rocket
###

__TOLERATE_ROCKET_MINSTRET = True
def is_tolerate_rocket_minstret():
    return __TOLERATE_ROCKET_MINSTRET
if __TOLERATE_ROCKET_MINSTRET:
    print('WARNING: Tolerating one bug: __TOLERATE_ROCKET_MINSTRET')

###
# Xiangshan
###

__TOLERATE_XIANGSHAN_MINSTRET = False
def is_tolerate_xiangshan_minstret():
    return __TOLERATE_XIANGSHAN_MINSTRET
if __TOLERATE_XIANGSHAN_MINSTRET:
    print('WARNING: Tolerating one bug: __TOLERATE_Xiangshan_MINSTRET')

# Toleration function for timing the reduction
def tolerate_bug_for_eval_reduction(design_name: str , is_activate: bool = True):
    global __TOLERATE_BOOM_MINSTRET
    global __TOLERATE_ROCKET_MINSTRET
    if design_name == 'boom':
        __TOLERATE_BOOM_MINSTRET = is_activate
        print(f"WARNING: Tolerating one bug for evaluating reduction (activate: {is_activate}): __TOLERATE_BOOM_MINSTRET")
    elif design_name == 'rocket':
        __TOLERATE_ROCKET_MINSTRET = is_activate
        print(f"WARNING: Tolerating one bug for evaluating reduction (activate: {is_activate}): __TOLERATE_ROCKET_MINSTRET")
    else:
        raise Exception('Unknown design name in __tolerate_bug_for_eval_reduction: ' + design_name)


# Toleration function for timing the reduction
# Design name is simply used for sanity checking
# @param is_activate: if false, then de-tolerate the bug
def tolerate_bug_for_bug_timing(design_name: str, bug_name: str, is_activate: bool):
    global __TOLERATE_BOOM_MINSTRET
    global __TOLERATE_ROCKET_MINSTRET

    # BOOM

    if bug_name == 'b1':
        assert design_name == 'boom-b1', 'Bug b1 is only for boom-b1'
    elif bug_name == 'b2':
        assert design_name == 'boom', 'Bug b2 is only for boom'
        __TOLERATE_BOOM_MINSTRET = is_activate
        if is_activate:
            print('WARNING: Tolerating one bug for timing: __TOLERATE_BOOM_MINSTRET')
        else:
            print('INFO: De-tolerating one bug for timing: __TOLERATE_BOOM_MINSTRET')

    # Rocket

    elif bug_name == 'r1':
        assert design_name == 'rocket', 'Bug r1 is only for rocket'
        __TOLERATE_ROCKET_MINSTRET = is_activate
        if is_activate:
            print('WARNING: Tolerating one bug for timing: __TOLERATE_ROCKET_MINSTRET')
        else:
            print('INFO: De-tolerating one bug for timing: __TOLERATE_ROCKET_MINSTRET')

    # Other

    else:
        raise NotImplementedError(f'Unknown bug `{bug_name}`')
