from nicegui import ui, app, run
from backend.vcenter import VCenterManager
import asyncio
import time

# --- 設定管理 (支援多 VC) ---
import json
import os
import threading
import html as _html_mod

# ── MD4 相容性修補 (Python 3.9+ / OpenSSL 3.x 停用 MD4，NTLM 驗證需要此修補) ──
import hashlib
try:
    hashlib.new('md4')
except ValueError:
    from Crypto.Hash import MD4 as _MD4_impl

    class _MD4Shim:
        name = 'md4'; digest_size = 16; block_size = 64
        def __init__(self, d=b''): self._h = _MD4_impl.new(d)
        def update(self, d): self._h.update(d); return self
        def digest(self): return self._h.digest()
        def hexdigest(self): return self._h.hexdigest()
        def copy(self): c = _MD4Shim(); c._h = self._h.copy(); return c

    _orig_hashlib_new = hashlib.new
    def _patched_hashlib_new(name, *args, **kwargs):
        if name.lower() == 'md4': return _MD4Shim(args[0] if args else b'')
        return _orig_hashlib_new(name, *args, **kwargs)
    hashlib.new = _patched_hashlib_new
# ── MD4 修補結束 ──

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ServerPool, FIRST

# ── AD 連線設定（由 config.json 載入，此處僅宣告變數）──
AD_DOMAIN           = ''
AD_SERVER_IPS       = []
AD_SERVICE_USER     = ''
AD_SERVICE_PASSWORD = ''
ALLOWED_AD_GROUP    = ''
AD_BASE_DN          = ''

def authenticate_ad(username, password):
    """AD 驗證：Service Account 搜尋 → 使用者 bind 驗證密碼 → 群組授權"""
    global AD_BASE_DN

    # 統一帳號格式為純 sAMAccountName
    if '\\' in username:   username = username.split('\\', 1)[1]
    elif '/' in username:  username = username.split('/', 1)[1]
    elif '@' in username:  username = username.split('@', 1)[0]
    username = username.strip()

    servers = [Server(ip, get_info=ALL) for ip in AD_SERVER_IPS]
    server_pool = ServerPool(servers, pool_strategy=FIRST)
    full_svc = f"{AD_DOMAIN}\\{AD_SERVICE_USER}" if '\\' not in AD_SERVICE_USER else AD_SERVICE_USER

    try:
        # Step 1: Service Account 連線搜尋使用者
        conn = Connection(server_pool, user=full_svc, password=AD_SERVICE_PASSWORD,
                          authentication=NTLM, auto_bind=True)
        if not AD_BASE_DN:
            try:
                if conn.server and conn.server.info:
                    AD_BASE_DN = conn.server.info.other.get('defaultNamingContext', [None])[0]
            except Exception:
                pass
            if not AD_BASE_DN:
                return False, '無法自動偵測 Base DN，請手動設定 AD_BASE_DN'

        conn.search(AD_BASE_DN, f'(&(objectClass=user)(sAMAccountName={username}))',
                    attributes=['distinguishedName', 'memberOf', 'displayName'],
                    search_scope=SUBTREE)
        if not conn.entries:
            return False, '找不到該使用者帳號'

        entry = conn.entries[0]
        display_name = entry.displayName.value if 'displayName' in entry else username
        member_of    = entry.memberOf.value    if 'memberOf'    in entry else []
        conn.unbind()

        # Step 2: 使用使用者帳密驗證密碼
        user_conn = Connection(server_pool, user=f"{AD_DOMAIN}\\{username}",
                               password=password, authentication=NTLM)
        if not user_conn.bind():
            return False, '密碼錯誤'
        user_conn.unbind()

        # Step 3: 檢查群組授權
        if isinstance(member_of, str):
            member_of = [member_of]
        for gdn in member_of:
            if f"CN={ALLOWED_AD_GROUP}" in gdn or ALLOWED_AD_GROUP.lower() in gdn.lower():
                return True, {'id': username, 'name': display_name}
        return False, f'驗證通過，但您不在授權群組 ({ALLOWED_AD_GROUP}) 內'

    except Exception as e:
        return False, f'AD 連線或驗證錯誤: {e}'

CONFIG_FILE = 'config.json'
_config_lock = threading.Lock()

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                data = json.load(f)
            # 向下相容：舊格式為 list
            if isinstance(data, list):
                return {'vcenter': data, 'ad': {}}
            return data
        except Exception as e:
            print(f"[警告] 讀取設定檔失敗: {e}")
    return {'vcenter': [], 'ad': {}}

def save_config(vcenter_list, ad_config=None):
    with _config_lock:
        with open(CONFIG_FILE, 'w') as f:
            json.dump({'vcenter': vcenter_list, 'ad': ad_config or {}}, f, indent=4, ensure_ascii=False)

# --- 狀態管理 ---
class State:
    def __init__(self):
        self.vms = []
        self.hosts = []
        self.managers = {} # 修改為字典，支援多個 Manager
        cfg = load_config()
        self.vc_configs = cfg['vcenter']
        self.ad_config  = cfg.get('ad', {})

state = State()

def _apply_ad_config(cfg):
    """將 ad_config dict 套用至全域 AD 連線變數"""
    global AD_DOMAIN, AD_SERVER_IPS, AD_SERVICE_USER, AD_SERVICE_PASSWORD, ALLOWED_AD_GROUP, AD_BASE_DN
    if cfg.get('domain'):           AD_DOMAIN           = cfg['domain']
    if cfg.get('servers'):          AD_SERVER_IPS       = cfg['servers']
    if cfg.get('service_user'):     AD_SERVICE_USER     = cfg['service_user']
    if cfg.get('service_password'): AD_SERVICE_PASSWORD = cfg['service_password']
    if cfg.get('allowed_group'):    ALLOWED_AD_GROUP    = cfg['allowed_group']
    if cfg.get('base_dn'):          AD_BASE_DN          = cfg['base_dn']

_apply_ad_config(state.ad_config)

# 防止多個 browser session 同時對同一台 VC 重複發起連線
_connecting: set = set()

# --- 資料更新邏輯 ---
async def fetch_all_data():
    all_hosts = []
    all_vms = []
    
    for vc_ip, manager in state.managers.items():
        if manager.si:
            try:
                info = await run.io_bound(manager.get_infrastructure_info)
                if not info:
                    continue
                # 為資料標註來源 VC
                for h in info['hosts']: h['vc'] = vc_ip
                for v in info['vms']: v['vc'] = vc_ip
                
                all_hosts.extend(info['hosts'])
                all_vms.extend(info['vms'])
            except Exception as e:
                print(f"[{vc_ip}] 背景更新失敗: {e}")
                
    state.hosts = all_hosts
    state.vms = all_vms

# --- App-level 背景輪詢（無瀏覽器也持續執行，保持 session 存活）---
async def background_poller():
    while True:
        await asyncio.sleep(10)
        if state.managers:
            await fetch_all_data()

# --- UI 渲染邏輯 ---
def _hl(text: str, query: str) -> str:
    """將 text 中第一個符合 query 的片段以黃色 <mark> 標記，其餘 HTML 轉義。"""
    text = str(text)
    if not query:
        return _html_mod.escape(text)
    idx = text.lower().find(query.lower())
    if idx == -1:
        return _html_mod.escape(text)
    before = _html_mod.escape(text[:idx])
    match  = _html_mod.escape(text[idx:idx + len(query)])
    after  = _html_mod.escape(text[idx + len(query):])
    return f'{before}<mark style="background:#fef08a;border-radius:2px;padding:0 1px">{match}</mark>{after}'


def _usage_color(pct):
    if pct < 0.2: return '#22c55e'
    if pct < 0.4: return '#84cc16'
    if pct < 0.6: return '#eab308'
    if pct < 0.8: return '#f97316'
    return '#ef4444'

def _render_compute(panel_containers):
    """結構不變時原地更新數值；結構改變（新增/移除主機或VM）時才全量重建。"""
    search = panel_containers.get('compute_search', '').lower().strip()

    filtered_hosts = []
    filtered_vms_by_host = {}
    for h in state.hosts:
        hn = h['name']
        host_vms = [v for v in state.vms if v.get('host') == hn]
        if search:
            if search in hn.lower():
                matched = host_vms  # 主機名稱符合 → 顯示全部 VM
            else:
                matched = [v for v in host_vms if search in v['name'].lower()]
            if not matched:
                continue
        else:
            matched = host_vms
        filtered_hosts.append(h)
        filtered_vms_by_host[hn] = matched

    host_order = [h['name'] for h in filtered_hosts]
    vms_by_host = {
        hn: [v['name'] for v in sorted(filtered_vms_by_host[hn], key=lambda v: v.get('cpu_usage', 0), reverse=True)]
        for hn in host_order
    }
    refs = panel_containers.get('compute_refs')
    if refs and refs['host_order'] == host_order and refs['vms_by_host'] == vms_by_host and refs.get('search') == search:
        # ── 原地更新 ──
        vms_by_name = {v['name']: v for v in state.vms}
        for host in state.hosts:
            hn = host['name']
            hr = refs['hosts'].get(hn)
            if not hr:
                continue
            total_cpu = host.get('cpu_total_mhz', 1) or 1
            total_mem = host.get('memory_total_mb', 1) or 1
            cpu_pct = host.get('cpu_usage_mhz', 0) / total_cpu
            mem_pct = host.get('memory_usage_mb', 0) / total_mem
            hr['cpu_label'].text = f"CPU: {int(cpu_pct*100)}%  ({host.get('cpu_usage_mhz', 0) / 1000:.2f} / {total_cpu / 1000:.2f} GHz)"
            hr['cpu_bar'].value = cpu_pct
            hr['cpu_bar']._props['color'] = _usage_color(cpu_pct)
            hr['cpu_bar'].update()
            hr['mem_label'].text = f"Memory: {int(mem_pct*100)}%  ({host.get('memory_usage_mb', 0) / 1024:.2f} / {total_mem / 1024:.2f} GB)"
            hr['mem_bar'].value = mem_pct
            hr['mem_bar']._props['color'] = _usage_color(mem_pct)
            hr['mem_bar'].update()
            for vm_name in vms_by_host[hn]:
                vm = vms_by_name.get(vm_name)
                vr = hr['vms'].get(vm_name)
                if not vm or not vr:
                    continue
                cpu_mhz = vm.get('cpu_usage', 0)
                mem_gb  = vm.get('memory_usage_mb', 0) / 1024
                vr['cpu_mhz'].text = f"{cpu_mhz} MHz"
                vr['tt_cpu'].text  = f'CPU 使用：{cpu_mhz} MHz'
                vr['tt_mem'].text  = f'RAM 使用：{mem_gb:.2f} GB'
        return

    # ── 全量重建 ──
    panel_containers.pop('compute_refs', None)
    panel_containers['compute'].clear()
    refs = {'host_order': host_order, 'vms_by_host': vms_by_host, 'hosts': {}, 'search': search}
    with panel_containers['compute']:
        if not filtered_hosts:
            ui.label('無主機資料' if not state.hosts else '找不到符合的主機或 VM').classes('text-slate-400 italic p-4')
        else:
            with ui.element('div').classes(
                'w-full max-w-screen-2xl mx-auto p-2 sm:p-4 '
                'grid gap-4 sm:gap-6 grid-cols-1 md:grid-cols-2 xl:grid-cols-3 items-stretch'
            ):
                for host in filtered_hosts:
                    host_name = host['name']
                    total_cpu = host.get('cpu_total_mhz', 1) or 1
                    total_mem = host.get('memory_total_mb', 1) or 1
                    cpu_pct   = host.get('cpu_usage_mhz', 0) / total_cpu
                    mem_pct   = host.get('memory_usage_mb', 0) / total_mem
                    host_vms  = sorted(
                        filtered_vms_by_host.get(host_name, []),
                        key=lambda v: v.get('cpu_usage', 0), reverse=True
                    )
                    hr = {'vms': {}}
                    with ui.card().classes(
                        'w-full p-0 overflow-hidden flex flex-col h-full '
                        'bg-slate-100 shadow-lg border border-slate-200'
                    ):
                        with ui.row().classes('w-full items-center bg-[#4B4B4B] text-white p-3 m-0 flex-nowrap'):
                            ui.icon('dns', size='md').classes('flex-shrink-0')
                            with ui.column().classes('ml-2 gap-0 flex-grow min-w-0'):
                                ui.html(_hl(host_name, search)).classes('text-lg font-bold leading-tight truncate w-full')
                                ui.label(host.get('vc', 'Unknown VC')).classes('text-xs opacity-70 leading-tight truncate w-full')
                        with ui.column().classes('px-4 pt-4 pb-2 w-full'):
                            hr['cpu_label'] = ui.label(
                                f"CPU: {int(cpu_pct*100)}%  ({host.get('cpu_usage_mhz', 0) / 1000:.2f} / {total_cpu / 1000:.2f} GHz)"
                            ).classes('text-sm font-bold text-slate-600')
                            hr['cpu_bar'] = ui.linear_progress(value=cpu_pct, color=_usage_color(cpu_pct)).classes('mt-1 h-2 w-full')
                            hr['mem_label'] = ui.label(
                                f"Memory: {int(mem_pct*100)}%  ({host.get('memory_usage_mb', 0) / 1024:.2f} / {total_mem / 1024:.2f} GB)"
                            ).classes('text-sm font-bold text-slate-600 mt-3')
                            hr['mem_bar'] = ui.linear_progress(value=mem_pct, color=_usage_color(mem_pct)).classes('mt-1 h-2 w-full')
                        ui.separator().classes('mx-4 my-2 bg-slate-300')
                        with ui.column().classes('w-full bg-slate-200 p-3 flex-grow'):
                            with ui.row().classes('w-full justify-between items-center mb-2 flex-nowrap'):
                                ui.label('Virtual Machines').classes('font-bold text-slate-600')
                                ui.badge(f'{len(host_vms)}', color='red-9')
                            if not host_vms:
                                ui.label('此主機上沒有 VM').classes('text-slate-400 italic text-sm')
                            else:
                                with ui.element('div').classes(
                                    'w-full overflow-y-auto h-[248px] flex flex-col gap-2 pr-1'
                                ):
                                    for vm in host_vms:
                                        is_on         = vm['power_state'] == 'poweredOn'
                                        icon_color    = '#8C1C13' if is_on else '#94a3b8'
                                        vm_bg         = 'bg-white' if is_on else 'bg-slate-50'
                                        cpu_alloc     = vm.get('num_cpu', 0)
                                        cpu_usage_mhz = vm.get('cpu_usage', 0)
                                        mem_alloc_gb  = vm.get('memory_size_mb', 0) / 1024
                                        mem_usage_gb  = vm.get('memory_usage_mb', 0) / 1024
                                        with ui.row().classes(
                                            f'w-full items-center justify-between border border-slate-300 '
                                            f'rounded {vm_bg} p-2 shadow-sm flex-nowrap'
                                        ):
                                            with ui.row().classes('items-center flex-grow min-w-0 flex-nowrap'):
                                                ui.icon('computer', color=icon_color, size='sm').classes('flex-shrink-0')
                                                ui.html(_hl(vm['name'], search)).classes('ml-2 text-sm truncate flex-grow text-slate-700')
                                            cpu_mhz_lbl = ui.label(f"{cpu_usage_mhz} MHz").classes('text-xs font-mono text-[#8C1C13] w-[60px] text-right flex-shrink-0')
                                            with ui.tooltip().classes('text-sm'):
                                                ui.label(f'CPU 配置：{cpu_alloc} vCPU').classes('font-bold')
                                                tt_cpu = ui.label(f'CPU 使用：{cpu_usage_mhz} MHz').classes('text-xs')
                                                ui.separator().classes('my-1')
                                                ui.label(f'RAM 配置：{mem_alloc_gb:.1f} GB').classes('font-bold')
                                                tt_mem = ui.label(f'RAM 使用：{mem_usage_gb:.2f} GB').classes('text-xs')
                                        hr['vms'][vm['name']] = {'cpu_mhz': cpu_mhz_lbl, 'tt_cpu': tt_cpu, 'tt_mem': tt_mem}
                    refs['hosts'][host_name] = hr
    panel_containers['compute_refs'] = refs

def _render_storage(panel_containers):
    """結構不變時原地更新磁碟用量；結構改變時全量重建。"""
    search = panel_containers.get('storage_search', '').lower().strip()

    # 依所有使用到的 datastores 分組（VM 可出現在多張卡片）
    datastores: dict = {}
    for vm in state.vms:
        for ds in vm.get('datastores', [vm.get('datastore', 'Unknown')]):
            if not ds:
                continue
            if ds not in datastores:
                datastores[ds] = []
            if vm not in datastores[ds]:
                datastores[ds].append(vm)

    # 套用搜尋篩選
    if search:
        datastores = {
            ds: [v for v in vms if search in v['name'].lower() or search in ds.lower()]
            for ds, vms in datastores.items()
        }
        datastores = {ds: vms for ds, vms in datastores.items() if vms}

    ds_order   = list(datastores.keys())
    vms_by_ds  = {
        ds: [v['name'] for v in sorted(vms, key=lambda v: v.get('disk_committed_gb', 0), reverse=True)]
        for ds, vms in datastores.items()
    }
    refs = panel_containers.get('storage_refs')
    if refs and refs['ds_order'] == ds_order and refs['vms_by_ds'] == vms_by_ds and refs.get('search') == search:
        # ── 原地更新 ──
        vms_by_name = {v['name']: v for v in state.vms}
        for ds_name, vm_refs_map in refs['datastores'].items():
            for vm_name, vm_refs in vm_refs_map.items():
                vm = vms_by_name.get(vm_name)
                if not vm:
                    continue
                disk_gb      = vm.get('disk_committed_gb', 0)
                disk_prov_gb = vm.get('disk_provisioned_gb', 0)
                vm_refs['disk_label'].text = f'{disk_gb} GB'
                vm_refs['tt_prov'].text    = f'硬碟部屬量：{disk_prov_gb} GB'
                vm_refs['tt_used'].text    = f'硬碟實際用量：{disk_gb} GB'
        return

    # ── 全量重建 ──
    panel_containers.pop('storage_refs', None)
    panel_containers['storage'].clear()
    refs = {'ds_order': ds_order, 'vms_by_ds': vms_by_ds, 'datastores': {}, 'search': search}
    with panel_containers['storage']:
        with ui.element('div').classes(
            'w-full max-w-screen-2xl mx-auto p-2 sm:p-4 '
            'grid gap-4 sm:gap-6 grid-cols-1 md:grid-cols-2 xl:grid-cols-3 items-start'
        ):
            for ds_name, vms in datastores.items():
                sorted_vms  = sorted(vms, key=lambda v: v.get('disk_committed_gb', 0), reverse=True)
                ds_vm_refs  = {}
                with ui.card().classes(
                    'w-full p-0 overflow-hidden flex flex-col '
                    'bg-slate-100 border border-slate-200 shadow-md'
                ):
                    with ui.row().classes('w-full items-center text-white p-3 m-0 flex-nowrap').style('background-color: #e8714a'):
                        ui.icon('storage', size='md').classes('flex-shrink-0')
                        ui.html(_hl(ds_name, search)).classes('text-lg font-bold ml-2 truncate flex-grow')
                    with ui.column().classes('p-3 w-full'):
                        ui.label(f"掛載了 {len(vms)} 台 VM").classes('text-sm mb-2 font-bold').style('color: #e8714a')
                        with ui.element('div').classes(
                            'w-full overflow-y-auto max-h-[248px] flex flex-col gap-2 pr-1'
                        ):
                            for vm in sorted_vms:
                                disk_gb      = vm.get('disk_committed_gb', 0)
                                disk_prov_gb = vm.get('disk_provisioned_gb', 0)
                                vmdk_files   = vm.get('vmdk_files', [])
                                with ui.row().classes('w-full items-center border border-slate-300 rounded bg-white p-2 shadow-sm flex-nowrap'):
                                    ui.icon('computer', color='#e8714a', size='sm').classes('flex-shrink-0')
                                    ui.html(_hl(vm['name'], search)).classes('ml-2 text-sm truncate flex-grow text-slate-700')
                                    disk_lbl = ui.label(f'{disk_gb} GB').classes('text-xs font-mono flex-shrink-0 ml-2 text-right w-[64px]').style('color: #e8714a')
                                    with ui.tooltip().classes('text-sm'):
                                        if vmdk_files:
                                            ui.label('虛擬硬碟').classes('font-bold')
                                            for vmdk in vmdk_files:
                                                ui.label(vmdk).classes('text-xs font-mono')
                                            ui.separator().classes('my-1')
                                        tt_prov = ui.label(f'硬碟部屬量：{disk_prov_gb} GB').classes('font-bold')
                                        tt_used = ui.label(f'硬碟實際用量：{disk_gb} GB').classes('text-xs')
                                ds_vm_refs[vm['name']] = {'disk_label': disk_lbl, 'tt_prov': tt_prov, 'tt_used': tt_used}
                refs['datastores'][ds_name] = ds_vm_refs
    panel_containers['storage_refs'] = refs

def _render_network(panel_containers):
    """結構不變時原地更新開關機數量、IP、電源狀態色；結構改變時全量重建。"""
    def get_network_keys(vm):
        net = vm.get('network', '')
        if isinstance(net, list):
            keys = [n.strip() for n in net if n and n.strip()]
        elif isinstance(net, str) and net.strip():
            keys = [net.strip()]
        else:
            keys = []
        return keys or ['未知網路群組']

    def _ip_sort(v):
        return [int(x) if x.isdigit() else 0 for x in str(v.get('ip') or '0.0.0.0').split('.')]

    def _get_nic_ip(vm, grp_name):
        """取得 VM 在指定 network group 的 NIC IP（過濾 IPv6 與 169.254.x.x）"""
        for nic in vm.get('nics', []):
            if nic.get('network') == grp_name:
                for ip in nic.get('ips', []):
                    if ip and not ip.startswith('169.254') and ':' not in ip:
                        return ip
                if nic.get('ips'):
                    return nic['ips'][0]
        # fallback: 主要 IP
        ip = vm.get('ip', '') or ''
        return ip if ip not in ('Unknown', '') else '—'

    search = panel_containers.get('network_search', '').lower().strip()

    net_groups = {}
    for vm in state.vms:
        for key in get_network_keys(vm):
            if key not in net_groups:
                net_groups[key] = []
            if vm not in net_groups[key]:
                net_groups[key].append(vm)
    sorted_groups = sorted(net_groups.items(), key=lambda x: (x[0] == '未知網路群組', x[0]))

    # 套用搜尋篩選（卡片名稱或 VM 名稱皆可）
    if search:
        filtered_sg = []
        for grp, vms in sorted_groups:
            if search in grp.lower():
                filtered_sg.append((grp, vms))   # 整組卡片名稱符合 → 顯示全部 VM
            else:
                matched = [v for v in vms if search in v['name'].lower()]
                if matched:
                    filtered_sg.append((grp, matched))
        sorted_groups = filtered_sg

    grp_order  = [g[0] for g in sorted_groups]
    vms_by_grp = {
        grp: [v['name'] for v in sorted(vms, key=_ip_sort)]
        for grp, vms in sorted_groups
    }

    refs = panel_containers.get('network_refs')
    if refs and refs['grp_order'] == grp_order and refs['vms_by_grp'] == vms_by_grp and refs.get('search') == search:
        # ── 原地更新 ──
        vms_by_name = {v['name']: v for v in state.vms}
        for grp_name, grp_refs in refs['groups'].items():
            grp_vms   = net_groups.get(grp_name, [])
            if search:
                grp_vms = [v for v in grp_vms if search in v['name'].lower()]
            on_count  = sum(1 for v in grp_vms if v.get('power_state') == 'poweredOn')
            off_count = len(grp_vms) - on_count
            grp_refs['on_label'].text  = f'開機 {on_count}'
            grp_refs['off_label'].text = f'關機 {off_count}'
            for vm_name, vm_refs in grp_refs['vms'].items():
                vm = vms_by_name.get(vm_name)
                if not vm:
                    continue
                is_on  = vm.get('power_state') == 'poweredOn'
                vm_refs['ip_label'].text = _get_nic_ip(vm, grp_name)
                new_color = '#8C1C13' if is_on else '#94a3b8'
                vm_refs['icon']._props['color'] = new_color
                vm_refs['icon'].update()
                if is_on:
                    vm_refs['row'].classes(add='bg-white', remove='bg-slate-50')
                else:
                    vm_refs['row'].classes(add='bg-slate-50', remove='bg-white')
        return

    # ── 全量重建 ──
    panel_containers.pop('network_refs', None)
    panel_containers['network'].clear()
    refs = {'grp_order': grp_order, 'vms_by_grp': vms_by_grp, 'groups': {}, 'search': search}
    with panel_containers['network']:
        with ui.element('div').classes(
            'w-full max-w-screen-2xl mx-auto p-2 sm:p-4 '
            'grid gap-4 sm:gap-6 grid-cols-1 md:grid-cols-2 xl:grid-cols-3 items-start'
        ):
            for grp_name, grp_vms in sorted_groups:
                on_count  = sum(1 for v in grp_vms if v.get('power_state') == 'poweredOn')
                off_count = len(grp_vms) - on_count
                grp_refs  = {'vms': {}}
                with ui.card().classes(
                    'w-full p-0 overflow-hidden flex flex-col '
                    'bg-sky-50 border border-sky-200 shadow-md'
                ):
                    with ui.row().classes('w-full items-center bg-sky-500 text-white p-3 m-0 flex-nowrap'):
                        ui.icon('lan', size='md').classes('flex-shrink-0')
                        with ui.column().classes('ml-2 gap-0 flex-grow min-w-0'):
                            ui.html(_hl(grp_name, search)).classes('text-base font-bold leading-tight truncate w-full')
                            ui.label('Network Group').classes('text-xs opacity-70 leading-tight')
                    with ui.column().classes('p-3 w-full'):
                        with ui.row().classes('w-full justify-between items-center mb-1 flex-nowrap'):
                            with ui.row().classes('items-center gap-3'):
                                with ui.row().classes('items-center gap-1'):
                                    ui.icon('circle', color='#8C1C13', size='xs')
                                    grp_refs['on_label'] = ui.label(f'開機 {on_count}').classes('text-xs text-slate-500')
                                with ui.row().classes('items-center gap-1'):
                                    ui.icon('circle', color='#94a3b8', size='xs')
                                    grp_refs['off_label'] = ui.label(f'關機 {off_count}').classes('text-xs text-slate-500')
                            ui.badge(f'{len(grp_vms)} 台', color='grey-8')
                        ui.separator().classes('my-2 bg-slate-300')
                        with ui.element('div').classes('w-full overflow-y-auto max-h-[248px] flex flex-col gap-2 pr-1'):
                            for vm in sorted(grp_vms, key=_ip_sort):
                                is_on      = vm.get('power_state') == 'poweredOn'
                                icon_color = '#8C1C13' if is_on else '#94a3b8'
                                vm_bg      = 'bg-white' if is_on else 'bg-slate-50'
                                ip_str     = _get_nic_ip(vm, grp_name)
                                row = ui.row().classes(
                                    f'w-full items-center justify-between border border-slate-300 '
                                    f'rounded {vm_bg} px-2 shadow-sm flex-nowrap h-9'
                                )
                                with row:
                                    with ui.row().classes('items-center flex-grow min-w-0 flex-nowrap'):
                                        vm_icon = ui.icon('computer', color=icon_color, size='sm').classes('flex-shrink-0')
                                        ui.html(_hl(vm['name'], search)).classes('ml-2 text-sm truncate flex-grow text-slate-700')
                                        # NIC hover tooltip（req 8）
                                        nic = next((n for n in vm.get('nics', []) if n.get('network') == grp_name), None)
                                        if nic:
                                            with ui.tooltip().classes('text-sm p-2'):
                                                ui.label(f"[{nic.get('label', '網路介面卡')}]").classes('font-bold text-xs')
                                                ui.label(f"[介面卡類型] {nic.get('adapter_type', '—')}").classes('text-xs')
                                                ui.label(f"[MAC 位址] {nic.get('mac', '—')}").classes('text-xs font-mono')
                                                ui.label(f"[DirectPath I/O] {nic.get('passthrough', '非作用中')}").classes('text-xs')
                                                ui.label(f"[網路] {nic.get('network', '—')}").classes('text-xs')
                                    ip_lbl = ui.label(ip_str).classes('text-xs font-mono text-[#8C1C13] w-[110px] text-right flex-shrink-0')
                                grp_refs['vms'][vm['name']] = {'row': row, 'icon': vm_icon, 'ip_label': ip_lbl}
                refs['groups'][grp_name] = grp_refs
    panel_containers['network_refs'] = refs


def _export_vmlist_csv(panel_containers):
    import csv, io
    all_rows = panel_containers.get('vmlist_all_rows', [])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['VM 名稱', '來源 vCenter', 'IP 位址', '電源狀態', '所在主機 (ESXi)', '儲存區', 'Network Group'])
    for row in all_rows:
        writer.writerow([
            row.get('name', ''),
            row.get('vc', ''),
            row.get('ip', ''),
            '開機' if row.get('power_state') == 'poweredOn' else '關機',
            row.get('host', ''),
            row.get('datastore', ''),
            row.get('network', ''),
        ])
    ui.download(output.getvalue().encode('utf-8-sig'), 'vm_list.csv')


def _render_vmlist(panel_containers):
    def normalize_vm_row(vm):
        row = dict(vm)
        # Network Group
        raw_net = row.get('network', '')
        net_list = [n for n in (raw_net if isinstance(raw_net, list) else [raw_net]) if n]
        row['network']      = '\n'.join(net_list) if net_list else '—'
        row['network_list'] = net_list if net_list else ['—']
        # IP
        ips = row.get('all_ips', [])
        if not ips:
            raw = row.get('ip', '') or ''
            ips = [raw] if raw and raw != 'Unknown' else []
        row['ip']      = '\n'.join(ips) if ips else '—'
        row['ip_list'] = ips if ips else ['—']
        # 儲存區
        dss = [d for d in row.get('datastores', [row.get('datastore', '')]) if d]
        row['datastore']  = '\n'.join(dss) if dss else '—'
        row['ds_list']    = dss if dss else ['—']
        return row

    all_vm_rows = [normalize_vm_row(v) for v in state.vms]
    for row in all_vm_rows:
        row['_id'] = f"{row.get('vc', '')}::{row.get('name', '')}"
    panel_containers['vmlist_all_rows'] = all_vm_rows

    search_raw = panel_containers.get('vmlist_search', '').strip()
    search = search_raw.lower()
    if search:
        vm_rows = [r for r in all_vm_rows if
                   search in r.get('name', '').lower() or
                   search in r.get('ip', '').lower() or
                   search in r.get('host', '').lower() or
                   search in r.get('network', '').lower() or
                   search in r.get('datastore', '').lower() or
                   search in r.get('vc', '').lower()]
    else:
        vm_rows = all_vm_rows

    for row in vm_rows:
        row['name_hl']     = _hl(row.get('name', ''), search_raw)
        row['host_hl']     = _hl(row.get('host', ''), search_raw)
        row['vc_hl']       = _hl(row.get('vc', ''), search_raw)
        row['ip_list_hl']  = [_hl(v, search_raw) for v in row.get('ip_list', ['—'])]
        row['net_list_hl'] = [_hl(v, search_raw) for v in row.get('network_list', ['—'])]
        row['ds_list_hl']  = [_hl(v, search_raw) for v in row.get('ds_list', ['—'])]

    if 'vmlist_tbl' in panel_containers:
        # 原地更新資料列，保留頁碼與排序狀態（不清空 DOM）
        panel_containers['vmlist_tbl'].rows = vm_rows
        panel_containers['vmlist_tbl'].update()
    else:
        panel_containers['vmlist'].clear()
        with panel_containers['vmlist']:
            with ui.card().classes('w-full max-w-screen-xl mx-auto m-4 bg-white border border-slate-200 shadow-sm'):
                with ui.row().classes('w-full items-center justify-between mb-4 flex-wrap gap-2'):
                    ui.label('VM 總覽').classes('text-xl font-bold text-[#8C1C13]')
                    with ui.row().classes('items-center gap-2'):
                        search_input = ui.input(placeholder='搜尋 VM / IP / 主機...').props('dense outlined clearable').classes('w-56 text-sm')
                        async def _on_vmlist_search(e, pc=panel_containers):
                            val = e.value or ''
                            pc['vmlist_search'] = val
                            await asyncio.sleep(0.3)
                            if pc.get('vmlist_search') == val:
                                _render_vmlist(pc)
                        search_input.on_value_change(_on_vmlist_search)
                        panel_containers['vmlist_search_input'] = search_input
                        ui.button(icon='download', on_click=lambda: _export_vmlist_csv(panel_containers)).props('flat round color=primary').tooltip('匯出 CSV')
                columns = [
                    {'name': 'name',      'label': 'VM 名稱',         'field': 'name',        'required': True, 'align': 'left',   'sortable': True, 'style': 'min-width:90px'},
                    {'name': 'state',     'label': '電源狀態',        'field': 'power_state', 'sortable': True, 'align': 'center', 'style': 'width:80px; min-width:80px'},
                    {'name': 'ip',        'label': 'IP 地址',         'field': 'ip',          'sortable': True, 'align': 'left',   'style': 'min-width:140px'},
                    {'name': 'network',   'label': 'Network Group',   'field': 'network',     'sortable': True, 'align': 'left',   'style': 'min-width:160px'},
                    {'name': 'host',      'label': '所在主機 (ESXi)', 'field': 'host',        'sortable': True, 'align': 'left',   'style': 'min-width:160px'},
                    {'name': 'datastore', 'label': '儲存區',          'field': 'datastore',   'sortable': True, 'align': 'left',   'style': 'min-width:140px'},
                    {'name': 'vc',        'label': '來源 vCenter',    'field': 'vc',          'sortable': True, 'align': 'left',   'style': 'min-width:120px'},
                ]
                tbl = ui.table(
                    columns=columns, rows=vm_rows, row_key='_id',
                    pagination={'rowsPerPage': 20}
                ).classes('w-full text-slate-700').props('flat :rows-per-page-options="[20, 100, 0]"')
                tbl.add_slot('body-cell-name', '''
                    <q-td :props="props">
                        <span v-html="props.row.name_hl || props.row.name"></span>
                    </q-td>
                ''')
                tbl.add_slot('body-cell-state', '''
                    <q-td :props="props" class="text-center">
                        <q-badge
                            :color="props.row.power_state === 'poweredOn' ? 'positive' : 'negative'"
                            :label="props.row.power_state === 'poweredOn' ? 'ON' : 'OFF'"
                            class="text-white text-xs font-bold px-2 py-1"
                        />
                    </q-td>
                ''')
                # 多值欄位：每行獨立顯示，支援 highlight
                tbl.add_slot('body-cell-ip', '''
                    <q-td :props="props" class="py-1">
                        <div v-for="(v,i) in (props.row.ip_list_hl || props.row.ip_list || [props.row.ip])" :key="i"
                             class="text-xs font-mono whitespace-nowrap leading-6" v-html="v"></div>
                    </q-td>
                ''')
                tbl.add_slot('body-cell-network', '''
                    <q-td :props="props" class="py-1">
                        <div v-for="(v,i) in (props.row.net_list_hl || props.row.network_list || [props.row.network])" :key="i"
                             class="text-xs whitespace-nowrap leading-6" v-html="v"></div>
                    </q-td>
                ''')
                tbl.add_slot('body-cell-host', '''
                    <q-td :props="props">
                        <span v-html="props.row.host_hl || props.row.host"></span>
                    </q-td>
                ''')
                tbl.add_slot('body-cell-datastore', '''
                    <q-td :props="props" class="py-1">
                        <div v-for="(v,i) in (props.row.ds_list_hl || props.row.ds_list || [props.row.datastore])" :key="i"
                             class="text-xs whitespace-nowrap leading-6" v-html="v"></div>
                    </q-td>
                ''')
                tbl.add_slot('body-cell-vc', '''
                    <q-td :props="props">
                        <span v-html="props.row.vc_hl || props.row.vc"></span>
                    </q-td>
                ''')
                panel_containers['vmlist_tbl'] = tbl


def build_dashboard_shell(panel_containers, container):
    """只執行一次：建立 tabs 外殼與各 panel 空容器"""
    with container:
        with ui.tabs().classes(
            'w-full bg-white text-slate-700 shadow-sm rounded-t-lg border-b border-slate-200'
        ) as tabs:
            compute_tab = ui.tab('運算 (Compute)').classes('text-[#8C1C13]')
            storage_tab = ui.tab('儲存 (Storage)').classes('text-[#8C1C13]')
            network_tab = ui.tab('網路 (Network)').classes('text-[#8C1C13]')
            vmlist_tab  = ui.tab('VM 總覽').classes('text-[#8C1C13]')

        with ui.tab_panels(tabs, value=compute_tab).classes('w-full bg-transparent p-0'):
            with ui.tab_panel(compute_tab):
                with ui.row().classes('w-full items-center px-4 pt-3 pb-1 gap-2'):
                    ui.icon('search', size='sm').classes('text-slate-400')
                    cs = ui.input(placeholder='搜尋主機或 VM...').props('dense outlined clearable').classes('w-64 text-sm')
                    panel_containers['compute_search'] = ''
                    async def _on_cs(e, pc=panel_containers):
                        val = e.value or ''
                        pc['compute_search'] = val
                        await asyncio.sleep(0.3)
                        if pc.get('compute_search') == val:
                            _render_compute(pc)
                    cs.on_value_change(_on_cs)
                panel_containers['compute'] = ui.element('div').classes('w-full')

            with ui.tab_panel(storage_tab):
                with ui.row().classes('w-full items-center px-4 pt-3 pb-1 gap-2'):
                    ui.icon('search', size='sm').classes('text-slate-400')
                    ss = ui.input(placeholder='搜尋儲存區或 VM...').props('dense outlined clearable').classes('w-64 text-sm')
                    panel_containers['storage_search'] = ''
                    async def _on_ss(e, pc=panel_containers):
                        val = e.value or ''
                        pc['storage_search'] = val
                        await asyncio.sleep(0.3)
                        if pc.get('storage_search') == val:
                            _render_storage(pc)
                    ss.on_value_change(_on_ss)
                panel_containers['storage'] = ui.element('div').classes('w-full')

            with ui.tab_panel(network_tab):
                with ui.row().classes('w-full items-center px-4 pt-3 pb-1 gap-2'):
                    ui.icon('search', size='sm').classes('text-slate-400')
                    ns = ui.input(placeholder='搜尋網路群組或 VM...').props('dense outlined clearable').classes('w-64 text-sm')
                    panel_containers['network_search'] = ''
                    async def _on_ns(e, pc=panel_containers):
                        val = e.value or ''
                        pc['network_search'] = val
                        await asyncio.sleep(0.3)
                        if pc.get('network_search') == val:
                            _render_network(pc)
                    ns.on_value_change(_on_ns)
                panel_containers['network'] = ui.element('div').classes('w-full')

            with ui.tab_panel(vmlist_tab):
                panel_containers['vmlist_search'] = ''
                panel_containers['vmlist'] = ui.element('div').classes('w-full')


def render_dashboard(panel_containers):
    """資料更新（Timer 觸發）：所有面板原地更新數值，不清空 DOM，不打擾使用者。
    結構改變（新增/移除主機或VM）時才執行全量重建。"""
    if not panel_containers:
        return
    _render_compute(panel_containers)
    _render_storage(panel_containers)
    _render_network(panel_containers)
    _render_vmlist(panel_containers)


# --- 主佈局 ---
@ui.page('/')
def main_page():
    if not app.storage.user.get('authenticated'):
        return ui.navigate.to('/login')

    # ── 改為淺色模式
    ui.dark_mode().disable()
    ui.colors(primary='#8C1C13', secondary='#4B4B4B', accent='#D4BFBF')

    panel_containers = {}

    # ── 左側 Drawer（桌面固定展開、手機可收合）
    with ui.left_drawer(value=True, bordered=True).props('breakpoint=768 width=280').classes('bg-white shadow-sm') as sidebar:
        ui.label('基礎設施總覽').classes('text-xl font-bold mb-2 text-[#8C1C13]')

        with ui.card().classes('w-full bg-[#F5EDED] border border-[#C9B5B5] shadow-sm p-3 mb-6'):
            total_hosts_label = ui.label('ESXi 主機: 0').classes('text-md text-[#8C1C13] font-bold')
            total_vms_label = ui.label('虛擬機 (VM): 0').classes('text-md text-[#8C1C13] font-bold mt-2')
            last_update_label = ui.label('最後更新: -').classes('text-xs text-slate-400 mt-3')

        def update_stats():
            total_hosts_label.text = f'ESXi 主機: {len(state.hosts)}'
            total_vms_label.text = f'虛擬機 (VM): {len(state.vms)}'

        ui.separator().classes('my-4 bg-slate-200')

        ui.label('vCenter 連線狀態').classes('font-bold mb-2 text-slate-600')
        vc_status_container = ui.column().classes('w-full gap-1')

        def refresh_vc_status():
            vc_status_container.clear()
            with vc_status_container:
                if not state.vc_configs:
                    ui.label('尚無設定，請點右上角齒輪新增').classes('text-slate-400 text-xs italic')
                    return
                for vc in state.vc_configs:
                    ip = vc['ip']
                    is_connected = ip in state.managers and state.managers[ip].si is not None
                    icon_color = '#22c55e' if is_connected else '#8C1C13'
                    status_text = '已連線' if is_connected else '未連線'
                    with ui.row().classes('items-center gap-2 px-1 py-0.5'):
                        ui.icon('circle', color=icon_color, size='xs')
                        ui.label(ip).classes('text-xs text-slate-600 truncate flex-grow')
                        ui.label(status_text).classes(
                            f'text-xs {"text-green-500" if is_connected else "text-[#8C1C13]"} flex-shrink-0'
                        )

        refresh_vc_status()

        status_label = ui.label('準備連線...').classes('text-slate-400 font-bold mt-4')

        def update_data():
            """UI 重繪：從 state 更新畫面（資料由 background_poller 維護）"""
            try:
                render_dashboard(panel_containers)
                update_stats()
                last_update_label.text = f'最後更新: {time.strftime("%H:%M:%S")}'
            except RuntimeError:
                # client 已關閉（瀏覽器頁籤離開），停用 timer 避免持續觸發
                _update_timer.active = False

        _update_timer = ui.timer(10.0, update_data)

        async def connect_all():
            if not state.vc_configs:
                ui.notify('請先至設定頁新增 vCenter', type='warning')
                return

            # 分辨「已連線」vs「需要重連」，避免誤報失敗
            already_connected = [
                vc['ip'] for vc in state.vc_configs
                if vc['ip'] in state.managers and state.managers[vc['ip']].si
            ]
            need_connect = [
                vc for vc in state.vc_configs
                if (vc['ip'] not in state.managers or not state.managers[vc['ip']].si)
                   and vc['ip'] not in _connecting
            ]

            if not need_connect:
                # 全部已連線 → 靜默更新資料，不跳通知、不顯示錯誤
                status_label.text = f'已連線 {len(already_connected)}/{len(state.vc_configs)} 座 (即時更新中)'
                status_label.classes(replace='text-[#8C1C13] font-bold mt-4')
                await fetch_all_data()
                update_data()
                return

            status_label.text = '正在連線...'
            status_label.classes(replace='font-bold mt-2')

            success_count = 0
            for vc in need_connect:
                ip = vc['ip']
                _connecting.add(ip)
                try:
                    manager = VCenterManager(
                        host=ip,
                        user=vc['user'],
                        password=vc['password']
                    )
                    is_connected = await run.io_bound(manager.connect)
                    if is_connected:
                        state.managers[ip] = manager
                        success_count += 1
                finally:
                    _connecting.discard(ip)

            refresh_vc_status()

            total_connected = len(already_connected) + success_count
            if total_connected > 0:
                status_label.text = f'已連線 {total_connected}/{len(state.vc_configs)} 座 (即時更新中)'
                status_label.classes(replace='text-[#8C1C13] font-bold mt-4')
                await fetch_all_data()
                update_data()
                if success_count > 0:
                    ui.notify(f'成功連線 {success_count} 座 vCenter', type='positive', position='top')
            else:
                status_label.text = '全數連線失敗'
                status_label.classes(replace='text-red-500 font-bold mt-4')
                ui.notify('無法連線至任何 vCenter', type='negative', position='top')

        ui.button('連線所有 vCenter', on_click=connect_all).classes('w-full mt-4 shadow-md').props('color="primary"')

        # 頁面開啟時自動觸發：已連線則靜默更新，未連線才重連
        ui.timer(0.5, connect_all, once=True)

    # Header：白底 + 暗紅底線
    with ui.header().classes('items-center justify-between bg-white border-b border-[#C9B5B5] shadow-sm'):
        with ui.row().classes('items-center gap-2'):
            ui.button(icon='menu', on_click=sidebar.toggle).props('flat round color=primary')
            ui.icon('cloud', size='xl', color='#8C1C13')
            ui.label('vCenter 維運儀表板').classes('text-xl font-bold ml-1 text-slate-700')
        with ui.row().classes('items-center gap-3'):
            ui.label('Real-time API Monitor').classes('text-sm text-slate-400 hidden sm:block')
            ui.label(app.storage.user.get('display_name', '')).classes('text-sm font-bold text-[#8C1C13] hidden sm:block')
            ui.button(icon='settings', on_click=lambda: ui.navigate.to('/settings')).props('flat round color=primary').tooltip('vCenter 設定')
            ui.button(icon='logout', on_click=lambda: ui.navigate.to('/logout')).props('flat round color=primary').tooltip('登出')

    # 儀表板內容：淺灰背景
    with ui.column().classes('w-full bg-slate-100 p-4') as dashboard_container:
        build_dashboard_shell(panel_containers, dashboard_container)

@ui.page('/settings')
def settings_page():
    if not app.storage.user.get('authenticated'):
        return ui.navigate.to('/login')

    ui.dark_mode().disable()
    ui.colors(primary='#8C1C13', secondary='#4B4B4B', accent='#D4BFBF')

    with ui.header().classes('items-center bg-white border-b border-[#C9B5B5] shadow-sm gap-3'):
        ui.button(icon='arrow_back', on_click=lambda: ui.navigate.to('/')).props('flat round color=primary').tooltip('返回儀表板')
        ui.icon('settings', size='lg', color='#8C1C13')
        ui.label('系統設定').classes('text-2xl font-bold text-slate-800')

    # ── 左側導覽（比照主頁 Drawer 風格）
    with ui.left_drawer(value=True, bordered=True).props('breakpoint=768 width=220').classes('bg-white shadow-sm'):
        ui.label('設定項目').classes('text-xs font-bold text-slate-400 uppercase tracking-widest px-4 pt-5 pb-3')
        with ui.tabs(value='vcenter').props('vertical indicator-color="primary"').classes('w-full') as stabs:
            ui.tab('vcenter', label='vCenter 連線', icon='cloud').props('align=left no-caps').classes(
                'w-full justify-start text-slate-600 font-medium'
            )
            ui.tab('ad', label='AD 驗證設定', icon='security').props('align=left no-caps').classes(
                'w-full justify-start text-slate-600 font-medium'
            )

    # ── 主內容：頁籤切換（slide 動畫）
    with ui.tab_panels(stabs, value='vcenter').props(
        'animated transition-prev="slide-right" transition-next="slide-left"'
    ).classes('w-full bg-slate-100 min-h-screen'):

        # ─── vCenter 連線 ───
        with ui.tab_panel('vcenter').classes('p-0'):
            with ui.column().classes('w-full max-w-lg mx-auto p-4 sm:p-8 gap-6'):
                ui.label('新增 vCenter').classes('text-lg font-bold text-[#8C1C13]')
                with ui.card().classes('w-full p-4 bg-white border border-slate-200 shadow-sm'):
                    host_input = ui.input('vCenter IP / Hostname').classes('w-full text-slate-700')
                    user_input = ui.input('使用者帳號').classes('w-full text-slate-700')
                    pass_input = ui.input('密碼', password=True).classes('w-full text-slate-700')

                    def add_vc():
                        ip_val   = host_input.value.strip()
                        user_val = user_input.value.strip()
                        pass_val = pass_input.value
                        if not ip_val or not user_val or not pass_val:
                            ui.notify('請填寫完整資訊', type='warning')
                            return
                        if any(vc['ip'] == ip_val for vc in state.vc_configs):
                            ui.notify('此 vCenter 已存在', type='warning')
                            return
                        state.vc_configs.append({'ip': ip_val, 'user': user_val, 'password': pass_val})
                        save_config(state.vc_configs, state.ad_config)
                        ui.notify(f'已新增 vCenter: {ip_val}', type='positive')
                        host_input.value = ''
                        user_input.value = ''
                        pass_input.value = ''
                        refresh_vc_list()

                    ui.button('新增至清單', on_click=add_vc).classes('w-full mt-3').props('color="secondary"')

                ui.label('已設定的 vCenter').classes('text-lg font-bold text-[#8C1C13]')
                vc_list_container = ui.column().classes('w-full gap-2')

                def refresh_vc_list():
                    vc_list_container.clear()
                    with vc_list_container:
                        if not state.vc_configs:
                            ui.label('尚無設定').classes('text-slate-400 text-sm italic')
                            return
                        for vc in state.vc_configs:
                            ip = vc['ip']
                            is_connected = ip in state.managers and state.managers[ip].si is not None
                            bg_color   = 'bg-[#F5EDED] border-[#C9B5B5]' if is_connected else 'bg-slate-100 border-slate-300'
                            icon_color = '#8C1C13' if is_connected else '#94a3b8'
                            with ui.row().classes(f'w-full items-center justify-between border rounded p-3 {bg_color} flex-nowrap'):
                                with ui.row().classes('items-center flex-grow min-w-0 flex-nowrap'):
                                    ui.icon('cloud_done' if is_connected else 'cloud_off', color=icon_color).classes('flex-shrink-0')
                                    with ui.column().classes('ml-2 gap-0 min-w-0'):
                                        ui.label(ip).classes('font-bold text-sm text-slate-700 truncate')
                                        ui.label(vc['user']).classes('text-xs text-slate-400 truncate')
                                def delete_vc(ip_to_delete=ip):
                                    state.vc_configs = [c for c in state.vc_configs if c['ip'] != ip_to_delete]
                                    save_config(state.vc_configs, state.ad_config)
                                    if ip_to_delete in state.managers:
                                        del state.managers[ip_to_delete]
                                    refresh_vc_list()
                                ui.button(icon='delete', color='red', on_click=delete_vc).props('flat dense size=sm').classes('flex-shrink-0')

                refresh_vc_list()

        # ─── AD 驗證設定 ───
        with ui.tab_panel('ad').classes('p-0'):
            with ui.column().classes('w-full max-w-lg mx-auto p-4 sm:p-8 gap-6'):
                ui.label('AD 驗證設定').classes('text-lg font-bold text-[#8C1C13]')
                with ui.card().classes('w-full p-4 bg-white border border-slate-200 shadow-sm'):
                    ad_domain_input   = ui.input('AD Domain (NetBIOS Name)', value=AD_DOMAIN).classes('w-full text-slate-700')
                    ad_servers_input  = ui.input('AD Server IPs（多台以逗號分隔）', value=', '.join(AD_SERVER_IPS)).classes('w-full text-slate-700')
                    ad_svc_user_input = ui.input('Service Account 帳號', value=AD_SERVICE_USER).classes('w-full text-slate-700')
                    ad_svc_pwd_input  = ui.input('Service Account 密碼', value=AD_SERVICE_PASSWORD,
                                                  password=True, password_toggle_button=True).classes('w-full text-slate-700')
                    ad_group_input    = ui.input('允許登入的 AD 群組', value=ALLOWED_AD_GROUP).classes('w-full text-slate-700')
                    ad_basedn_input   = ui.input('Base DN', value=AD_BASE_DN).classes('w-full text-slate-700')

                    def save_ad_settings():
                        global AD_DOMAIN, AD_SERVER_IPS, AD_SERVICE_USER, AD_SERVICE_PASSWORD, ALLOWED_AD_GROUP, AD_BASE_DN
                        AD_DOMAIN           = ad_domain_input.value.strip()
                        AD_SERVER_IPS       = [s.strip() for s in ad_servers_input.value.split(',') if s.strip()]
                        AD_SERVICE_USER     = ad_svc_user_input.value.strip()
                        AD_SERVICE_PASSWORD = ad_svc_pwd_input.value
                        ALLOWED_AD_GROUP    = ad_group_input.value.strip()
                        AD_BASE_DN          = ad_basedn_input.value.strip()
                        state.ad_config = {
                            'domain':           AD_DOMAIN,
                            'servers':          AD_SERVER_IPS,
                            'service_user':     AD_SERVICE_USER,
                            'service_password': AD_SERVICE_PASSWORD,
                            'allowed_group':    ALLOWED_AD_GROUP,
                            'base_dn':          AD_BASE_DN,
                        }
                        save_config(state.vc_configs, state.ad_config)
                        ui.notify('AD 設定已儲存至 config.json', type='positive')

                    ui.button('儲存 AD 設定', on_click=save_ad_settings).classes('w-full mt-3').props('color="secondary"')


@ui.page('/login')
def login_page():
    ui.dark_mode().disable()
    ui.colors(primary='#8C1C13', secondary='#4B4B4B', accent='#D4BFBF')

    if app.storage.user.get('authenticated'):
        return ui.navigate.to('/')

    with ui.column().classes('w-full min-h-screen bg-slate-100 items-center justify-center'):
        with ui.card().classes(
            'w-full max-w-sm p-8 bg-white border border-[#C9B5B5] shadow-md rounded-lg'
        ):
            # 標題
            with ui.row().classes('items-center gap-3 justify-center mb-1'):
                ui.icon('cloud', size='xl', color='#8C1C13')
                ui.label('vCenter 維運儀表板').classes('text-xl font-bold text-slate-700')
            ui.label('請使用 AD 帳號登入').classes('text-xs text-slate-400 text-center w-full mb-5')

            # 錯誤訊息（預設隱藏）
            error_label = ui.label('').classes('text-sm text-[#8C1C13] w-full text-center hidden')

            username_input = ui.input('帳號 (AD User ID)', placeholder='請輸入 AD 帳號').classes('w-full')
            password_input = ui.input(
                '密碼', password=True, password_toggle_button=True, placeholder='請輸入密碼'
            ).classes('w-full')

            async def do_login():
                uname = username_input.value.strip()
                pwd   = password_input.value
                if not uname or not pwd:
                    error_label.text = '請輸入帳號與密碼'
                    error_label.classes(remove='hidden')
                    return

                # 本機管理帳號（緊急備援，不經過 AD）
                if uname == 'admin' and pwd == 'admin':
                    app.storage.user.update({
                        'authenticated': True,
                        'username':      'admin',
                        'display_name':  '本機管理員',
                    })
                    ui.navigate.to('/')
                    return

                login_btn.props(add='loading')
                error_label.classes(add='hidden')
                success, result = await run.io_bound(authenticate_ad, uname, pwd)
                login_btn.props(remove='loading')
                if success:
                    app.storage.user.update({
                        'authenticated':  True,
                        'username':       result['id'],
                        'display_name':   result['name'],
                    })
                    ui.navigate.to('/')
                else:
                    error_label.text = result
                    error_label.classes(remove='hidden')

            # Enter 鍵觸發登入
            password_input.on('keydown.enter', do_login)

            login_btn = ui.button('登入', on_click=do_login).classes('w-full mt-4').props('color="primary"')


@ui.page('/logout')
def logout_page():
    app.storage.user.clear()
    return ui.navigate.to('/login')


app.on_startup(lambda: asyncio.create_task(background_poller()))
ui.run(title='vCenter Dashboard v1.2', port=8082, reload=False, storage_secret='vc-dashboard-secret-2024')