import ssl
import atexit
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

class VCenterManager:
    def __init__(self, host, user, password, port=443):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.si = None
        self.content = None
        self._atexit_registered = False

    def _disconnect_on_exit(self):
        if self.si:
            try:
                Disconnect(self.si)
            except Exception:
                pass

    def connect(self):
        """建立 vCenter 連線"""
        try:
            context = ssl._create_unverified_context()
            self.si = SmartConnect(host=self.host, user=self.user, pwd=self.password, port=self.port, sslContext=context)
            self.content = self.si.RetrieveContent()
            if not self._atexit_registered:
                atexit.register(self._disconnect_on_exit)
                self._atexit_registered = True
            print(f"成功連接至 vCenter: {self.host}")
            return True
        except Exception as e:
            print(f"無法連接至 vCenter: {e}")
            return False

    def _fetch_data(self):
        """從 vCenter API 抓取 Host 與 VM 資料"""
        data = {"hosts": [], "vms": [], "datastores": {}}
        container_view = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [vim.HostSystem], True
        )
        host_systems = list(container_view.view)
        container_view.Destroy()

        for host in host_systems:
            try:
                summary = host.summary
                data["hosts"].append({
                    "name": host.name,
                    "cpu_usage_mhz": summary.quickStats.overallCpuUsage,
                    "memory_usage_mb": summary.quickStats.overallMemoryUsage,
                    "cpu_total_mhz": summary.hardware.cpuMhz * summary.hardware.numCpuCores,
                    "memory_total_mb": summary.hardware.memorySize / (1024 * 1024),
                    "model": summary.hardware.model or '',
                    "cpu_model": summary.hardware.cpuModel or '',
                    "num_cpu_threads": summary.hardware.numCpuThreads or 0,
                    "uptime_seconds": summary.quickStats.uptime or 0,
                })

                for vm in host.vm:
                    try:
                        vm_summary = vm.summary
                        vm_config = vm_summary.config
                        vm_guest = vm_summary.guest
                        vm_runtime = vm_summary.runtime
                        vm_quickStats = vm_summary.quickStats

                        networks = []
                        nics_data = []
                        vmdk_files = []
                        disk_provisioned_kb = 0

                        # 從 guest.net 取得每張 NIC 的 IP 列表（需要 VMware Tools）
                        guest_net_by_mac = {}
                        try:
                            if vm.guest and vm.guest.net:
                                for gnic in vm.guest.net:
                                    if gnic.macAddress:
                                        guest_net_by_mac[gnic.macAddress] = list(gnic.ipAddress or [])
                        except Exception:
                            pass

                        try:
                            for device in vm.config.hardware.device:
                                if isinstance(device, vim.vm.device.VirtualEthernetCard):
                                    backing = device.backing
                                    net_name = ''
                                    if hasattr(backing, 'network') and backing.network:
                                        net_name = backing.network.name
                                    elif hasattr(backing, 'deviceName') and backing.deviceName:
                                        net_name = backing.deviceName
                                    networks.append(net_name)

                                    mac = getattr(device, 'macAddress', '') or ''
                                    if isinstance(device, vim.vm.device.VirtualVmxnet3):
                                        adapter_type = 'VMXNET 3'
                                    elif isinstance(device, vim.vm.device.VirtualVmxnet2):
                                        adapter_type = 'VMXNET 2'
                                    elif isinstance(device, vim.vm.device.VirtualE1000e):
                                        adapter_type = 'E1000e'
                                    elif isinstance(device, vim.vm.device.VirtualE1000):
                                        adapter_type = 'E1000'
                                    else:
                                        adapter_type = type(device).__name__.replace('Virtual', '')
                                    label = (device.deviceInfo.label or '') if device.deviceInfo else ''
                                    passthrough = '作用中' if isinstance(device, vim.vm.device.VirtualSriovEthernetCard) else '非作用中'
                                    nics_data.append({
                                        'label': label,
                                        'adapter_type': adapter_type,
                                        'mac': mac,
                                        'network': net_name,
                                        'passthrough': passthrough,
                                        'ips': guest_net_by_mac.get(mac, []),
                                    })
                                elif isinstance(device, vim.vm.device.VirtualDisk):
                                    if hasattr(device.backing, 'fileName'):
                                        vmdk_files.append(device.backing.fileName)
                                    disk_provisioned_kb += device.capacityInKB or 0
                            networks = list(dict.fromkeys(networks))
                        except Exception:
                            networks = []
                            nics_data = []

                        # 彙整所有 NIC 的 IP
                        all_ips = []
                        for nic in nics_data:
                            for ip in nic.get('ips', []):
                                if ip and ip not in all_ips:
                                    all_ips.append(ip)
                        primary_ip = vm_guest.ipAddress or ''
                        if not all_ips and primary_ip and primary_ip != 'Unknown':
                            all_ips = [primary_ip]

                        # 從 vmdk 路徑解析所有使用到的儲存區
                        primary_ds = vm_config.vmPathName.split("]")[0].replace("[", "")
                        datastores_list = list(dict.fromkeys(
                            f.split(']')[0].replace('[', '').strip()
                            for f in vmdk_files if ']' in f
                        )) or [primary_ds]

                        data["vms"].append({
                            "name": vm_config.name,
                            "power_state": vm_runtime.powerState,
                            "cpu_usage": vm_quickStats.overallCpuUsage or 0,
                            "num_cpu": vm_config.numCpu or 0,
                            "memory_usage_mb": vm_quickStats.guestMemoryUsage or 0,
                            "memory_size_mb": vm_config.memorySizeMB or 0,
                            "ip": primary_ip or 'Unknown',
                            "all_ips": all_ips,
                            "datastore": primary_ds,
                            "datastores": datastores_list,
                            "host": host.name,
                            "network": networks,
                            "nics": nics_data,
                            "disk_committed_gb": round((vm_summary.storage.committed or 0) / (1024 ** 3), 1),
                            "disk_provisioned_gb": round(disk_provisioned_kb / (1024 * 1024), 1),
                            "vmdk_files": vmdk_files
                        })
                    except Exception:
                        continue

            except Exception as e:
                print(f"Error reading Host {host.name}: {e}")
                continue

        # ── Datastore 容量 ──
        ds_view = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [vim.Datastore], True
        )
        for ds in list(ds_view.view):
            try:
                s = ds.summary
                data["datastores"][s.name] = {
                    "capacity_gb": round(s.capacity / (1024 ** 3), 1),
                    "free_space_gb": round(s.freeSpace / (1024 ** 3), 1),
                }
            except Exception:
                continue
        ds_view.Destroy()

        return data

    def get_infrastructure_info(self):
        """取得 Host 與 VM 資料；session 過期或連線中斷時自動重連並重試一次"""
        try:
            return self._fetch_data()
        except (vim.fault.NotAuthenticated, vim.fault.InvalidLogin,
                ConnectionError, OSError, Exception) as e:
            # session 過期 / 網路中斷等皆嘗試重連
            if self.si is None:
                # 已被其他路徑清除，不重複重連
                return None
            print(f"[{self.host}] 資料抓取失敗（{type(e).__name__}），自動重連中...")
            self.si = None
            self.content = None
            if self.connect():
                try:
                    return self._fetch_data()
                except Exception as e2:
                    print(f"[{self.host}] 重連後仍失敗: {e2}")
                    return None
            return None
