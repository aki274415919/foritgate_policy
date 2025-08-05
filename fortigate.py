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

import re
from collections import defaultdict

def extract_vdom_blocks(conf_text):
    """提取每个vdom的独立配置块"""
    vdom_blocks = defaultdict(str)
    current_vdom = None
    vdom_re = re.compile(r'^edit\s+("?)(\S+)\1$')
    in_vdom = False
    vdom_name = ""
    for line in conf_text.splitlines():
        if line.strip() == 'config vdom':
            in_vdom = True
            continue
        if in_vdom:
            m = vdom_re.match(line.strip())
            if m:
                vdom_name = m.group(2)
                current_vdom = vdom_name
                vdom_blocks[vdom_name] = ""
                continue
            if line.strip() == "next":
                current_vdom = None
                continue
            if current_vdom:
                vdom_blocks[current_vdom] += line + '\n'
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

def parse_firewall_address(conf_text):
    results, lookup = {}, {}
    section = re.search(r'config firewall address(.*?)end', conf_text, re.DOTALL)
    if not section:
        return results, lookup
    blocks = re.findall(r'edit "([^"]+)"(.*?)next', section.group(1), re.DOTALL)
    for name, block in blocks:
        obj = {
            'name': name.strip(),
            'type': '', 'ip': '', 'fqdn': '', 'start-ip': '', 'end-ip': '', 'comment': ''
        }
        if m := re.search(r'set subnet ([\d\.]+) ([\d\.]+)', block):
            obj['type'] = 'ip'
            obj['ip'] = f"{m.group(1)}/{sum(bin(int(x)).count('1') for x in m.group(2).split('.'))}"
        if m := re.search(r'set fqdn "([^"]+)"', block):
            obj['type'] = 'fqdn'
            obj['fqdn'] = m.group(1)
        if m := re.search(r'set start-ip ([\d\.]+)', block):
            obj['type'] = 'ip-range'
            obj['start-ip'] = m.group(1)
            if m2 := re.search(r'set end-ip ([\d\.]+)', block):
                obj['end-ip'] = m2.group(1)
        if m := re.search(r'set comment "([^"]+)"', block):
            obj['comment'] = m.group(1)
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

        html.append("</ul>请检查这些对象名，或确认配置文件中有定义。</div>")

    else:
        html.append("<div style='background:#eaffea;color:#097;padding:10px 18px;'>没有未定义对象，一切OK。</div>")

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
    function toggleBranch(id) {
        var div = document.getElementById(id);
        if (div.style.display === 'none' || div.style.display === '') {
            div.style.display = 'block';
        } else {
            div.style.display = 'none';
        }
    }
    let review_result = {};
    document.querySelectorAll('.review-action').forEach(sel => {
        sel.onchange = function() {
            let pid = this.getAttribute('data-id');
            review_result[pid] = review_result[pid] || {};
            review_result[pid].action = this.value;
        }
    });
    document.querySelectorAll('.review-comment').forEach(inp => {
        inp.oninput = function() {
            let pid = this.getAttribute('data-id');
            review_result[pid] = review_result[pid] || {};
            review_result[pid].comment = this.value;
        }
    });
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

    # 1. 采集所有 VDOM（含 global）的对象/组/服务
    all_objs = collect_all_objects(conf_text)  # 你的新模块

    # 2. 解析所有 policy，带 vdom 信息
    policies = parse_all_policies(conf_text)   # 你需确保返回 [{'id':1,'vdom':'vdom1','srcaddr':...}, ...]
    
    # 3. 分 vdom 检查所有策略引用问题
    all_issues = []
    for vdom in all_objs:
        vdom_policies = [p for p in policies if p.get("vdom", "global") == vdom]
        issues = find_policy_reference_issues(vdom_policies, all_objs, vdom)
        all_issues.extend(issues)

    # 4. 输出结果
    if all_issues:
        print("==== 未定義・跨VDOM・引用錯誤 ====")
        for line in all_issues:
            print(line)
    else:
        print("すべてのポリシーの参照オブジェクトは正常に定義されています。")

if __name__ == "__main__":
    main()