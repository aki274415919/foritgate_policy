import re
import tkinter as tk
from tkinter import filedialog
from collections import defaultdict


def choose_conf_file():
    root = tk.Tk()
    root.withdraw()
    conf_path = filedialog.askopenfilename(
        title="FortiGate設定ファイルを選択",
        filetypes=[("Config Files", "*.conf"), ("All Files", "*.*")]
    )
    if not conf_path:
        print("ファイルが選択されませんでした。終了します。")
        exit()
    return conf_path


def extract_vdom_blocks(conf_text):
    vdom_blocks = defaultdict(str)
    current_vdom = None
    vdom_re = re.compile(r'^edit\s+("?)(\S+)\1$')
    in_vdom = False
    vdom_name = ""
    root_lines = []
    lines = conf_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip() == 'config vdom':
            # 进 vdom 区，前面都进root
            in_vdom = True
            i += 1
            break
        root_lines.append(line)
        i += 1

    # vdom区
    while in_vdom and i < len(lines):
        line = lines[i]
        if line.strip().startswith('edit '):
            vdom_name = line.strip().split(" ",1)[1].strip('"')
            current_vdom = vdom_name
            vdom_blocks[vdom_name] = ""
            i += 1
            while i < len(lines):
                l2 = lines[i]
                if l2.strip() == "next":
                    current_vdom = None
                    i += 1
                    break
                vdom_blocks[vdom_name] += l2 + '\n'
                i += 1
        elif line.strip() == 'end':
            # vdom段结束，跳出去处理剩下的root
            in_vdom = False
            i += 1
            break
        else:
            i += 1

    # 处理 vdom段之后的所有内容，也加到root
    while i < len(lines):
        root_lines.append(lines[i])
        i += 1

    vdom_blocks["root"] = "\n".join(root_lines)
    return vdom_blocks




def parse_objects_from_block(conf_block):
    """解析单个vdom或global中的对象"""
    addrs, addrgrps, srvs, srvgrps = {}, {}, {}, {}

    # 地址对象
    for m in re.finditer(r'config firewall address(.*?)end', conf_block, re.DOTALL):
        for m2 in re.finditer(r'edit "([^"]+)"', m.group(1)):
            addrs[m2.group(1)] = True

    # 地址组对象
    for m in re.finditer(r'config firewall addrgrp(.*?)end', conf_block, re.DOTALL):
        for g in re.finditer(r'edit "([^"]+)"(.*?)next', m.group(1), re.DOTALL):
            group_name = g.group(1)
            member_match = re.search(r'set member (.+)', g.group(2))
            if member_match:
                members = [x.strip('\"') for x in member_match.group(1).split()]
                addrgrps[group_name] = members

    # 服务对象
    for m in re.finditer(r'config firewall service custom(.*?)end', conf_block, re.DOTALL):
        for m2 in re.finditer(r'edit "([^"]+)"', m.group(1)):
            srvs[m2.group(1)] = True

    # 服务组对象
    for m in re.finditer(r'config firewall service group(.*?)end', conf_block, re.DOTALL):
        for g in re.finditer(r'edit "([^"]+)"(.*?)next', m.group(1), re.DOTALL):
            group_name = g.group(1)
            member_match = re.search(r'set member (.+)', g.group(2))
            if member_match:
                members = [x.strip('\"') for x in member_match.group(1).split()]
                srvgrps[group_name] = members

    return addrs, addrgrps, srvs, srvgrps

def collect_all_objects(conf_text):
    """全局和各VDOM的所有对象都采集一遍，返回大字典"""
    all_objs = {}
    # 1. 先处理global段（如果有）
    global_addrs, global_addrgrps, global_srvs, global_srvgrps = parse_objects_from_block(conf_text)
    all_objs['global'] = {
        "address": global_addrs,
        "addrgrp": global_addrgrps,
        "service": global_srvs,
        "servicegrp": global_srvgrps
    }
    # 2. 各vdom
    vdom_blocks = extract_vdom_blocks(conf_text)
    for vdom, vblock in vdom_blocks.items():
        addrs, addrgrps, srvs, srvgrps = parse_objects_from_block(vblock)
        all_objs[vdom] = {
            "address": addrs,
            "addrgrp": addrgrps,
            "service": srvs,
            "servicegrp": srvgrps
        }
    return all_objs

def resolve_addr(addr_name, all_objs, vdom='global', resolved=None):
    """递归查找地址组成员，返回所有底层地址对象"""
    if resolved is None:
        resolved = set()
    if addr_name in resolved:
        return set()  # 避免循环嵌套
    resolved.add(addr_name)
    addrgrp = all_objs[vdom].get('addrgrp', {})
    address = all_objs[vdom].get('address', {})
    # 递归：组
    if addr_name in addrgrp:
        all_members = set()
        for m in addrgrp[addr_name]:
            all_members |= resolve_addr(m, all_objs, vdom, resolved)
        return all_members
    # 原子对象
    elif addr_name in address:
        return {addr_name}
    else:
        return set()  # 未定义，或在别的vdom

def resolve_service(svc_name, all_objs, vdom='global', resolved=None):
    if resolved is None:
        resolved = set()
    if svc_name in resolved:
        return set()
    resolved.add(svc_name)
    grp = all_objs[vdom].get('servicegrp', {})
    single = all_objs[vdom].get('service', {})
    if svc_name in grp:
        all_members = set()
        for m in grp[svc_name]:
            all_members |= resolve_service(m, all_objs, vdom, resolved)
        return all_members
    elif svc_name in single:
        return {svc_name}
    else:
        return set()

def find_policy_reference_issues(policy_list, all_objs, vdom):
    issues = []
    known_addr = set(all_objs[vdom].get("address", {})) | set(all_objs[vdom].get("addrgrp", {}))
    known_svc = set(all_objs[vdom].get("service", {})) | set(all_objs[vdom].get("servicegrp", {}))
    # 支持全局对象引用
    global_addr = set(all_objs['global'].get("address", {})) | set(all_objs['global'].get("addrgrp", {}))
    global_svc = set(all_objs['global'].get("service", {})) | set(all_objs['global'].get("servicegrp", {}))

    for pol in policy_list:
        pid = pol.get('policyid') or pol.get('id') or pol.get('name', '[noid]')
        vdom_of_pol = pol.get('vdom', vdom)
        for k in ('srcaddr', 'dstaddr'):
            for addr in pol.get(k, '').split():
                if addr in {"all", "ALL"}:
                    continue
                if addr not in known_addr:
                    # 跨vdom定义
                    if addr in global_addr:
                        issues.append(f"ポリシーID {pid}: アドレス「{addr}」は global 定義")
                    else:
                        issues.append(f"ポリシーID {pid}: アドレス「{addr}」が {vdom} または global に未定義")
        for svc in pol.get('service', '').split():
            if svc in {"ALL", "all"}:
                continue
            if svc not in known_svc:
                if svc in global_svc:
                    issues.append(f"ポリシーID {pid}: サービス「{svc}」は global 定義")
                else:
                    issues.append(f"ポリシーID {pid}: サービス「{svc}」が {vdom} または global に未定義")
    return issues


def parse_firewall_vip(conf_text):
    results, lookup = {}, {}
    for m in re.finditer(
        r'config firewall vip(.*?)(?:^end$)',
        conf_text, re.DOTALL | re.MULTILINE | re.IGNORECASE
    ):
        segment = m.group(1)
        for m2 in re.finditer(r'edit "([^"]+)"(.*?)next', segment, re.DOTALL | re.IGNORECASE):
            name, block = m2.group(1), m2.group(2)
            obj = {
                'name': name.strip(),
                'extip': '', 'extintf': '', 'mappedip': '', 'type': '', 'comment': ''
            }
            if m3 := re.search(r'set extip ([\d\.]+)', block):
                obj['extip'] = m3.group(1)
            if m3 := re.search(r'set extintf "([^"]+)"', block):
                obj['extintf'] = m3.group(1)
            if m3 := re.search(r'set mappedip "([^"]+)"', block):
                obj['mappedip'] = m3.group(1)
            if m3 := re.search(r'set type (\w+)', block):
                obj['type'] = m3.group(1)
            if m3 := re.search(r'set comment "([^"]+)"', block):
                obj['comment'] = m3.group(1)
            results[obj['name']] = obj
            lookup[obj['name'].lower()] = obj['name']
    return results, lookup


def parse_firewall_address(conf_text):
    results, lookup = {}, {}
    # 能抓到所有独立块
    for m in re.finditer(
        r'config firewall address(.*?)(?:^end$)', 
        conf_text, re.DOTALL | re.MULTILINE | re.IGNORECASE
    ):
        segment = m.group(1)
        for m2 in re.finditer(r'edit "([^"]+)"(.*?)next', segment, re.DOTALL | re.IGNORECASE):
            name, block = m2.group(1), m2.group(2)
            obj = {
                'name': name.strip(),
                'type': '', 'ip': '', 'fqdn': '', 'start-ip': '', 'end-ip': '', 'comment': ''
            }
            if m3 := re.search(r'set subnet ([\d\.]+) ([\d\.]+)', block):
                obj['type'] = 'ip'
                obj['ip'] = f"{m3.group(1)}/{sum(bin(int(x)).count('1') for x in m3.group(2).split('.'))}"
            if m3 := re.search(r'set fqdn "([^"]+)"', block):
                obj['type'] = 'fqdn'
                obj['fqdn'] = m3.group(1)
            if m3 := re.search(r'set start-ip ([\d\.]+)', block):
                obj['type'] = 'ip-range'
                obj['start-ip'] = m3.group(1)
                if m4 := re.search(r'set end-ip ([\d\.]+)', block):
                    obj['end-ip'] = m4.group(1)
            if m3 := re.search(r'set comment "([^"]+)"', block):
                obj['comment'] = m3.group(1)
            results[obj['name']] = obj
            lookup[obj['name'].lower()] = obj['name']
    return results, lookup


def parse_firewall_addrgrp(conf_text):
    results, lookup = {}, {}
    section = re.search(r'config firewall addrgrp(.*?)end', conf_text, re.DOTALL)
    if not section:
        return results, lookup
    blocks = re.findall(r'edit "([^"]+)"(.*?)next', section.group(1), re.DOTALL)
    for name, block in blocks:
        obj = {'name': name.strip(), 'members': []}
        for m in re.finditer(r'set member((?: [^\n]+)+)', block):
            line = m.group(1).replace('\n', ' ')
            obj['members'] += [n.strip() for n in re.findall(r'"([^"]+)"', line)]
        results[obj['name']] = obj
        lookup[obj['name'].lower()] = obj['name']
    return results, lookup

def parse_firewall_service_custom(conf_text):
    results, lookup = {}, {}
    section = re.search(r'config firewall service custom(.*?)end', conf_text, re.DOTALL)
    if not section:
        return results, lookup
    blocks = re.findall(r'edit "([^"]+)"(.*?)next', section.group(1), re.DOTALL)
    for name, block in blocks:
        obj = {
            'name': name.strip(),
            'protocol': '', 'tcp_port': '', 'udp_port': '', 'comment': ''
        }
        if m := re.search(r'set protocol (\d+)', block):
            obj['protocol'] = m.group(1)
        if m := re.search(r'set tcp-portrange "([^"]+)"', block):
            obj['tcp_port'] = m.group(1)
        if m := re.search(r'set udp-portrange "([^"]+)"', block):
            obj['udp_port'] = m.group(1)
        if m := re.search(r'set comment "([^"]+)"', block):
            obj['comment'] = m.group(1)
        results[obj['name']] = obj
        lookup[obj['name'].lower()] = obj['name']
    return results, lookup

def parse_firewall_service_group(conf_text):
    results, lookup = {}, {}
    section = re.search(r'config firewall service group(.*?)end', conf_text, re.DOTALL)
    if not section:
        return results, lookup
    blocks = re.findall(r'edit "([^"]+)"(.*?)next', section.group(1), re.DOTALL)
    for name, block in blocks:
        obj = {'name': name.strip(), 'members': []}
        if m := re.search(r'set member (.+)', block):
            obj['members'] = [n.strip() for n in re.findall(r'"([^"]+)"', m.group(1))]
        results[obj['name']] = obj
        lookup[obj['name'].lower()] = obj['name']
    return results, lookup

def parse_firewall_policy(conf_text):
    results = []
    section = re.search(r'config firewall policy(.*?)end', conf_text, re.DOTALL)
    if not section:
        return results
    blocks = re.findall(r'edit (\d+)(.*?)next', section.group(1), re.DOTALL)
    for id, block in blocks:
        pol = {'id': id}
        for line in block.strip().splitlines():
            line = line.strip()
            if m := re.match(r'set (\w+) (.+)', line):
                key, value = m.group(1), m.group(2)
                if value.startswith('"'):
                    items = re.findall(r'"([^"]+)"', value)
                    if len(items) > 1:
                        value = items
                    elif items:
                        value = items[0]
                    else:
                        value = value.strip('"')
                pol[key] = value
        if 'name' not in pol:
            pol['name'] = ''
        results.append(pol)
    return results

# --- 递归展开地址组成员
def get_all_members(name, groups, group_lookup, _visited=None):
    if _visited is None:
        _visited = set()
    name_key = name.strip().lower()
    if name_key in _visited:
        return set()  # 防止死循环
    _visited.add(name_key)
    if name_key in group_lookup:
        real_name = group_lookup[name_key]
        group = groups.get(real_name)
        if group:
            all_members = set()
            for member in group.get('members', []):
                all_members |= get_all_members(member, groups, group_lookup, _visited)
            return all_members
    return {name.strip()}

# --- 递归展开服务组成员
def get_all_service_members(name, svc_groups, svc_lookup, _visited=None):
    if _visited is None:
        _visited = set()
    name_key = name.strip().lower()
    if name_key in _visited:
        return set()
    _visited.add(name_key)
    if name_key in svc_lookup:
        real_name = svc_lookup[name_key]
        group = svc_groups.get(real_name)
        if group:
            all_members = set()
            for member in group.get('members', []):
                all_members |= get_all_service_members(member, svc_groups, svc_lookup, _visited)
            return all_members
    return {name.strip()}

# --- 智能查找对象
def smart_obj_lookup(obj_name, obj_dict, obj_lookup):
    if not obj_name or not isinstance(obj_name, str):
        return None
    key = obj_name.strip().lower()
    if key in obj_lookup:
        real_name = obj_lookup[key]
        return obj_dict.get(real_name)
    return None

def render_obj_branch(
    obj_name,
    addresses, address_lookup,
    address_groups, addrgrp_lookup,
    services, service_lookup,
    service_groups, svcgrp_lookup,
    depth=0, seen=None
):
    if seen is None:
        seen = set()
    key = (obj_name.strip().lower() if isinstance(obj_name, str) else str(obj_name))
    if key in seen:
        return ""
    seen.add(key)

    if isinstance(obj_name, str) and obj_name.strip().lower() in {"any", "all"}:
        return f"<div class='object-level' style='color:green'><b>any</b></div>"

    obj = smart_obj_lookup(obj_name, addresses, address_lookup)
    if obj:
        # ===== 新增 VIP 判断并高亮 =====
        if obj.get('extip') and obj.get('mappedip'):   # 这两个字段VIP专有
            info = (
                f"{obj['name']} <span style='color:#06b;font-weight:bold'>[VIP]</span> "
                f"外部:{obj['extip']} → 内部:{obj['mappedip']} "
            )
            if obj.get('comment'):
                info += f"<span style='color:#aaa'>#{obj['comment']}</span>"
            return f"<div class='object-level' style='color:#06b;background:#e7f3ff;'>{info}</div>"
        # ===== 普通地址对象显示 =====
        info = f"{obj['name']} <span style='color:#999'>[{obj.get('type','')}]</span> "
        if obj.get('ip'): info += obj['ip'] + " "
        if obj.get('fqdn'): info += obj['fqdn'] + " "
        if obj.get('start-ip'): info += f"{obj['start-ip']}-{obj.get('end-ip','')}" + " "
        if obj.get('comment'): info += f"<span style='color:#aaa'>#{obj['comment']}</span>"
        return f"<div class='object-level'>{info}</div>"


    grp = smart_obj_lookup(obj_name, address_groups, addrgrp_lookup)
    if grp:
        html = f"<div class='object-level cell-flex' style='font-weight:bold;color:#148;'>"
        html += f"<span class='obj-name'>{grp['name']} <span style='color:#888'>(IPv4グループ)</span></span>"
        cell_id = f"obj-addrgrp-{grp['name']}"
        html += f"<span class='toggle-btn' onclick=\"toggleBranch('{cell_id}')\">[+]</span></div>"
        html += f"<div class='object-branch' id='{cell_id}'>"
        for member in grp['members']:
            html += render_obj_branch(
                member,
                addresses, address_lookup,
                address_groups, addrgrp_lookup,
                services, service_lookup,
                service_groups, svcgrp_lookup,
                depth+1, seen
            )
        html += "</div>"
        return html

    svc = smart_obj_lookup(obj_name, services, service_lookup)
    if svc:
        info = f"{svc['name']} <span style='color:#999'>[サービス]</span> "
        if svc.get('protocol'): info += f"proto:{svc['protocol']} "
        if svc.get('tcp_port'): info += f"TCP:{svc['tcp_port']} "
        if svc.get('udp_port'): info += f"UDP:{svc['udp_port']} "
        if svc.get('comment'): info += f"<span style='color:#aaa'>#{svc['comment']}</span>"
        return f"<div class='object-level'>{info}</div>"

    svcgrp = smart_obj_lookup(obj_name, service_groups, svcgrp_lookup)
    if svcgrp:
        html = f"<div class='object-level cell-flex' style='font-weight:bold;color:#148;'>"
        html += f"<span class='obj-name'>{svcgrp['name']} <span style='color:#888'>(サービスグループ)</span></span>"
        cell_id = f"obj-svcgrp-{svcgrp['name']}"
        html += f"<span class='toggle-btn' onclick=\"toggleBranch('{cell_id}')\">[+]</span></div>"
        html += f"<div class='object-branch' id='{cell_id}'>"
        for member in svcgrp['members']:
            html += render_obj_branch(
                member,
                addresses, address_lookup,
                address_groups, addrgrp_lookup,
                services, service_lookup,
                service_groups, svcgrp_lookup,
                depth+1, seen
            )
        html += "</div>"
        return html

    return f"<div class='object-level' style='color:red;'><b>[未定義]</b>{obj_name}</div>"

def collect_undefined_objs(policies,
    addresses, address_lookup,
    address_groups, addrgrp_lookup,
    services, service_lookup,
    service_groups, svcgrp_lookup):
    # 叶子对象名
    all_address_names = set([k.strip().lower() for k in addresses.keys()])
    all_service_names = set([k.strip().lower() for k in services.keys()])

    undefined_addr = set()
    undefined_svc = set()

    for pol in policies:
        for key in ('srcaddr', 'dstaddr'):
            val = pol.get(key)
            if not val:
                continue
            vals = val if isinstance(val, list) else [val]
            for v in vals:
                # 递归展开地址组成员
                for member in get_all_members(v, address_groups, addrgrp_lookup):
                    k = member.strip().lower()
                    if k not in all_address_names and k not in {"any", "all"}:
                        undefined_addr.add(member)
        for key in ('service',):
            val = pol.get(key)
            if not val:
                continue
            vals = val if isinstance(val, list) else [val]
            for v in vals:
                for member in get_all_service_members(v, service_groups, svcgrp_lookup):
                    k = member.strip().lower()
                    if k not in all_service_names and k not in {"any", "all"}:
                        undefined_svc.add(member)
    return undefined_addr, undefined_svc

def generate_policy_table(
    policies,
    addresses, address_lookup,
    address_groups, addrgrp_lookup,
    services, service_lookup,
    service_groups, svcgrp_lookup,
    undefined_addr, undefined_svc,
    out_file="policy_object_table.html"
):
    fields = [
        'id', 'name', 'action', 'status', 'srcintf', 'dstintf',
        'srcaddr', 'dstaddr', 'service', 'schedule',
        'logtraffic', 'comments', 'uuid', 'policyid'
    ]
    expand_fields = {"srcaddr", "dstaddr", "service"}
    html = [
        "<!DOCTYPE html><html lang='ja'><head><meta charset='UTF-8'>",
        "<title>FortiGateポリシービジュアライズ</title>",
        """
        <style>
        table { border-collapse: collapse; font-family: Consolas, monospace; font-size: 14px; min-width:1200px; }
        th, td { border: 1px solid #ccc; padding: 6px 10px; vertical-align: top; }
        th { background: #eee; font-weight: bold; }
            th { 
        background: #eee;
        font-weight: bold;
        position: sticky;
        top: 0;
        z-index: 2;
        }
        .object-branch { display:none; margin-top:6px; margin-left:6px; border-left:2px solid #999; padding-left:8px; background:#f9f9f9;}
        .object-level { margin-left:12px; }
        .cell-flex {
            display: flex;
            flex-direction: row;
            justify-content: space-between;
            align-items: center;
            min-width: 120px;
        }
        .obj-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .toggle-btn { flex-shrink: 0; margin-left: 10px; color: blue; cursor: pointer; }
        .review-row {background:#f6f6fa;}
        .review-cell {padding:6px 4px 10px 4px; border-bottom:1px solid #eee;}
        .row-del {background: #ffdddd !important; color: red !important; text-decoration: line-through;}
        .row-mod {background: #fff7cc !important;}
        .warnbox {background:#ffeeee;border:2px solid #f44;padding:14px 16px;font-size:16px;margin:18px 0;}
        </style>
        """,
        "</head><body>",
    ]

    # --- 在HTML前面输出未定义对象报表
    if undefined_addr or undefined_svc:
        html.append("<div class='warnbox'><b>未定义的对象：</b><ul>")

        if undefined_addr:
            addr_items = ", ".join(
                '<span style="color:#b00">{}</span>'.format(x) for x in sorted(undefined_addr)
            )
            html.append("<li><b>地址/组：</b> {}</li>".format(addr_items))

        if undefined_svc:
            svc_items = ", ".join(
                '<span style="color:#b00">{}</span>'.format(x) for x in sorted(undefined_svc)
            )
            html.append("<li><b>服务/组：</b> {}</li>".format(svc_items))

        html.append("</ul>これらのオブジェクト名を確認し、設定ファイルに定義されていることをご確認ください。</div>")

    else:
        html.append("<div style='background:#eaffea;color:#097;padding:10px 18px;'>未定義のオブジェクトはありません。すべて問題ありません。</div>")

    html.append("""<div style="margin:12px 0; text-align:center;">
    <button onclick="http.expandAllBranches()" style="margin-right:10px;">すべて展開</button>
    <button onclick="http.collapseAllBranches()" style="margin-right:10px;">すべて折りたたむ</button>
    <button onclick="http.clearSaved()" style="margin-right:10px; color:#b00;">記録をクリア</button>
    <button onclick="http.exportSaved()" style="margin-right:10px;">記録をエクスポート</button>
    <input type="file" id="importFile" style="display:none;" accept=".json" />
    <button onclick="document.getElementById('importFile').click()">記録をインポート</button>
    </div>""")
    html.append("<table>")
    html.append("<tr>" + "".join(f"<th>{f}</th>" for f in fields) + "<th>処理方法</th><th>コメント</th></tr>")
    for policy in policies:
        html.append("<tr>")
        for f in fields:
            val = policy.get(f, "")
            if f in expand_fields and val:
                vals = val if isinstance(val, list) else [val]
                cell_inner = []
                for idx, v in enumerate(vals):
                    cell_id = f"{f}-{policy.get('id','')}-{idx}"
                    branch_html = render_obj_branch(
                        v,
                        addresses, address_lookup,
                        address_groups, addrgrp_lookup,
                        services, service_lookup,
                        service_groups, svcgrp_lookup
                    )
                    cell_inner.append(
                        f"""<div class='cell-flex'>
                            <span class='obj-name'>{v}</span>
                            <span class='toggle-btn' onclick="toggleBranch('{cell_id}')">[+]</span>
                        </div>
                        <div class='object-branch' id='{cell_id}'>
                            {branch_html}
                        </div>"""
                    )
                html.append(f"<td>{''.join(cell_inner)}</td>")
            else:
                html.append(f"<td>{val}</td>")
        pid = policy.get('id','')
        html.append(
            f"""<td class='review-cell'>
                <select class="review-action" data-id="{pid}">
                  <option value="">--選択--</option>
                  <option value="allow">許可（残す）</option>
                  <option value="delete">削除</option>
                  <option value="modify">修正</option>
                </select>
            </td>
            <td class='review-cell'>
                <input class="review-comment" data-id="{pid}" placeholder="理由や補足" style="width:120px">
            </td>"""
        )
        html.append("</tr>")
    html.append("</table>")
    html.append("""
    <button id="big-submit" style="width:92%;height:40px;font-size:1.3em;margin:30px 4%;">全ての処理内容を提出する</button>
    <script>
    let review_result = {};

    // ----------------------
    // 展开/收缩
    window.http = window.http || {};
    window.http.expandAllBranches = function() {
        document.querySelectorAll('.object-branch').forEach(div => {
            div.style.display = 'block';
        });
    }
    window.http.collapseAllBranches = function() {
        document.querySelectorAll('.object-branch').forEach(div => {
            div.style.display = 'none';
        });
    }

    // --- 保存/恢复 ---
    function saveToLocal() {
        localStorage.setItem("fgt_policy_review", JSON.stringify(review_result));
    }
    function loadFromLocal() {
        try {
            const saved = localStorage.getItem("fgt_policy_review");
            if (saved) {
                review_result = JSON.parse(saved);
                // 回填到UI
                document.querySelectorAll('.review-action').forEach(sel => {
                    let pid = sel.getAttribute('data-id');
                    if (review_result[pid] && review_result[pid].action)
                        sel.value = review_result[pid].action;
                    else
                        sel.value = "";
                });
                document.querySelectorAll('.review-comment').forEach(inp => {
                    let pid = inp.getAttribute('data-id');
                    if (review_result[pid] && review_result[pid].comment)
                        inp.value = review_result[pid].comment;
                    else
                        inp.value = "";
                });
            }
        } catch(e) { review_result = {}; }
    }
    // 页面初始加载时自动恢复
    loadFromLocal();

    // --- 每次修改自动保存 ---
    document.querySelectorAll('.review-action').forEach(sel => {
        sel.onchange = function() {
            let pid = this.getAttribute('data-id');
            review_result[pid] = review_result[pid] || {};
            review_result[pid].action = this.value;
            saveToLocal();
        }
    });
    document.querySelectorAll('.review-comment').forEach(inp => {
        inp.oninput = function() {
            let pid = inp.getAttribute('data-id');
            review_result[pid] = review_result[pid] || {};
            review_result[pid].comment = this.value;
            saveToLocal();
        }
    });

    // ----------------------
    // 清空功能（日文弹窗）
    window.http.clearSaved = function() {
        if(confirm('すべての保存記録を本当に削除しますか？この操作は元に戻せません。')) {
            localStorage.removeItem("fgt_policy_review");
            review_result = {};
            // 清空页面所有输入
            document.querySelectorAll('.review-action').forEach(sel => sel.value = "");
            document.querySelectorAll('.review-comment').forEach(inp => inp.value = "");
            alert('ローカル保存がすべてクリアされました。');
        }
    };
    // 导出功能（日文弹窗）
    window.http.exportSaved = function() {
        const data = localStorage.getItem("fgt_policy_review");
        if(!data) return alert("エクスポートできる保存記録がありません。");
        const blob = new Blob([data], {type: "application/json"});
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = "fgt_policy_review.json";
        a.click();
        setTimeout(()=>URL.revokeObjectURL(a.href), 2000);
    };
    // 导入功能（日文弹窗）
    document.getElementById('importFile').addEventListener('change', function(e) {
        const file = e.target.files[0];
        if(!file) return;
        const reader = new FileReader();
        reader.onload = function(evt) {
            try {
                const imported = JSON.parse(evt.target.result);
                if(typeof imported === 'object') {
                    review_result = imported;
                    localStorage.setItem("fgt_policy_review", JSON.stringify(review_result));
                    // 自动回填到页面
                    document.querySelectorAll('.review-action').forEach(sel => {
                        let pid = sel.getAttribute('data-id');
                        if (review_result[pid] && review_result[pid].action)
                            sel.value = review_result[pid].action;
                        else
                            sel.value = "";
                    });
                    document.querySelectorAll('.review-comment').forEach(inp => {
                        let pid = inp.getAttribute('data-id');
                        if (review_result[pid] && review_result[pid].comment)
                            inp.value = review_result[pid].comment;
                        else
                            inp.value = "";
                    });
                    alert('インポートして自動的に復元しました。');
                } else {
                    alert("インポートした内容は有効な記録形式ではありません。");
                }
            } catch(e) {
                alert("インポートに失敗しました：" + e);
            }
        };
        reader.readAsText(file);
        this.value = ""; // 防止同文件再次选择无效
    });

    // ------ 还要保留 toggleBranch -----
    function toggleBranch(id) {
        var div = document.getElementById(id);
        if (div.style.display === 'none' || div.style.display === '') {
            div.style.display = 'block';
        } else {
            div.style.display = 'none';
        }
    }


    document.getElementById('big-submit').onclick = function() {
        let pageStyle = `
        <style>
        table { border-collapse: collapse; font-family: Consolas, monospace; font-size: 14px; min-width:1200px; }
        th, td { border: 1px solid #ccc; padding: 6px 10px; vertical-align: top; }
        th { background: #eee; font-weight: bold; }
        .object-branch { display:none; margin-top:6px; margin-left:6px; border-left:2px solid #999; padding-left:8px; background:#f9f9f9;}
        .object-level { margin-left:12px; }
        .cell-flex {
            display: flex;
            flex-direction: row;
            justify-content: space-between;
            align-items: center;
            min-width: 120px;
        }
        .obj-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .toggle-btn { flex-shrink: 0; margin-left: 10px; color: blue; cursor: pointer; }
        .review-row {background:#f6f6fa;}
        .review-cell {padding:6px 4px 10px 4px; border-bottom:1px solid #eee;}
        .row-del {background: #ffdddd !important; color: red !important; text-decoration: line-through;}
        .row-mod {background: #fff7cc !important;}
        .warnbox {background:#ffeeee;border:2px solid #f44;padding:14px 16px;font-size:16px;margin:18px 0;}
        </style>
        `;
        let table = document.querySelector("table").cloneNode(true);
        if (table.rows.length > 0 && table.rows[0].cells.length > 0) {
            table.rows[0].deleteCell(-1);
            table.rows[0].deleteCell(-1);
            let th1 = document.createElement("th");
            th1.textContent = "判定";
            table.rows[0].appendChild(th1);
            let th2 = document.createElement("th");
            th2.textContent = "コメント";
            table.rows[0].appendChild(th2);
        }
        for (let i = 1; i < table.rows.length; ++i) {
            let row = table.rows[i];
            let pid = row.cells[0].textContent.trim();
            let result = review_result[pid] || {};
            let action = result.action || '';
            let comment = result.comment || '';
            row.deleteCell(-1);
            row.deleteCell(-1);
            let td1 = document.createElement("td");
            td1.textContent = (
                action=="allow" ? "許可" : action=="delete" ? "削除" : action=="modify" ? "修正" : ""
            );
            row.appendChild(td1);
            let td2 = document.createElement("td");
            td2.textContent = comment;
            row.appendChild(td2);
            if(action=="delete") {
                row.classList.add("row-del");
            } else if(action=="modify") {
                row.classList.add("row-mod");
            }
        }
        alert("新しいウィンドウで右クリックして『印刷』を選び、PDFとして保存してお願いします。");
        let result_html = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>批判結果付きポリシー表</title>";
        result_html += pageStyle + "</head><body>";
        result_html += "<h2>批判処理結果付きポリシー一覧</h2>";
        result_html += table.outerHTML;
        result_html += "</body></html>";
        let w = window.open();
        w.document.write(result_html);
        w.document.close();
    };
    </script>
    """)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write('\n'.join(html))
    print("生成完了:", out_file)

def main():
    conf_path = choose_conf_file()
    with open(conf_path, "r", encoding="utf-8") as f:
        conf_text = f.read()
    addresses, address_lookup = parse_firewall_address(conf_text)
    address_groups, addrgrp_lookup = parse_firewall_addrgrp(conf_text)
    services, service_lookup = parse_firewall_service_custom(conf_text)
    service_groups, svcgrp_lookup = parse_firewall_service_group(conf_text)
    vips, vip_lookup = parse_firewall_vip(conf_text)    # <--- 新增
    addresses.update(vips)                              # <--- 合并到地址对象
    address_lookup.update(vip_lookup)
    policies = parse_firewall_policy(conf_text)
    # 递归检测未定义对象
    undefined_addr, undefined_svc = collect_undefined_objs(
        policies, addresses, address_lookup,
        address_groups, addrgrp_lookup,
        services, service_lookup,
        service_groups, svcgrp_lookup
    )
    generate_policy_table(
        policies, addresses, address_lookup,
        address_groups, addrgrp_lookup,
        services, service_lookup,
        service_groups, svcgrp_lookup,
        undefined_addr, undefined_svc,
        out_file="policy_object_table.html"
    )


if __name__ == "__main__":
    main()