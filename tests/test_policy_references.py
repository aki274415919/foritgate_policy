import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from fortigate import collect_all_objects, find_policy_reference_issues


def test_policy_referencing_undefined_address():
    conf = '''
config vdom
    edit root
        config firewall address
        end
    next
end
'''
    all_objs = collect_all_objects(conf)
    policy_list = [
        {'policyid': '1', 'srcaddr': 'UNDEFINED', 'dstaddr': 'all', 'service': 'ALL'}
    ]
    issues = find_policy_reference_issues(policy_list, all_objs, 'root')
    assert issues == ['ポリシーID 1: アドレス「UNDEFINED」が root または global に未定義']


def test_policy_referencing_global_address_from_vdom():
    conf = '''
config firewall address
    edit "GLOBAL_ADDR"
        set subnet 10.0.0.1 255.255.255.255
    next
end
config vdom
    edit root
        config firewall address
        end
    next
end
'''
    all_objs = collect_all_objects(conf)
    policy_list = [
        {'policyid': '1', 'srcaddr': 'GLOBAL_ADDR', 'dstaddr': 'all', 'service': 'ALL'}
    ]
    issues = find_policy_reference_issues(policy_list, all_objs, 'root')
    assert issues == ['ポリシーID 1: アドレス「GLOBAL_ADDR」は global 定義']
