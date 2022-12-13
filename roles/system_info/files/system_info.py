from dataclasses import dataclass
import platform
from typing import Dict, List, Optional
import psutil
import cpuinfo
import json
import dataclasses
import sys
import distro
import sys
import subprocess
import re
import jc
import base64
import mdstat

camel_pat = re.compile(r'([A-Z])')
under_pat = re.compile(r'_([a-z])')

def camel_to_underscore(name):
    return camel_pat.sub(lambda x: '_' + x.group(1).lower(), name)

def underscore_to_camel(name):
    return under_pat.sub(lambda x: x.group(1).upper(), name)


@dataclass
class CPU:
    model: str
    cores: int
    architecture: str

@dataclass
class CPUSummary:
    cores: int
    sockets: int
    cpus: List[CPU]

@dataclass
class Host:
    name: str
    os: str
    version: str
    kernel: str
    virtual: bool

@dataclass
class Memory:
    total: int

@dataclass
class Disk:
    name: str
    type: str
    serial_number: str
    size: int
    model: str
    vendor: Optional[str]
    transport: Optional[str]

@dataclass
class Partition:
    name: str
    size: int
    mount: str
    fstype: str

@dataclass
class Raid:
    disks: List[str]
    name: str
    size: int
    type: str

@dataclass
class Storage:
    partitions: List[Partition]
    disks: Optional[List[Disk]]
    raids: Optional[List[Raid]]

@dataclass
class IpV4Address:
    address: str
    netmask: str
    subnet_mask: str
    broadcast: str
    public: bool

@dataclass
class IpV6Address:
    address: str
    gateway: str
    subnet_mask: str
    broadcast: str
    type: str

@dataclass
class IpAddressesSummary:
    ipv4: List[IpV4Address]
    ipv6: List[IpV6Address]

@dataclass
class NIC:
    name: str
    ipv4: Optional[str] = None
    ipv6: Optional[List[str]] = None
    mac: str = None

@dataclass
class Network:
    ip_addresses: IpAddressesSummary
    nics: List[NIC]

@dataclass
class Machine:
    """Machine"""
    cpus: List[CPU]
    host: Host
    memory: Memory
    swap: Memory
    storage: List[Storage]
    network: Network

class EnhancedJSONEncoder(json.JSONEncoder):
        def default(self, o):
            if dataclasses.is_dataclass(o):
                return dataclasses.asdict(o)
            return super().default(o)


def run_lshw() -> dict:
    process = subprocess.run(
        ["sudo lshw -c disk -json"],
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if process.stderr != "":
        raise Exception(f"Recieved error running call:\n{process.stderr}")
    return json.loads(process.stdout)
  
def transport_type(device: str):
    if device.startswith("s"):
        return "sata"
    else:
        return "nvme"

def device_type(device: str) -> str:
    process = subprocess.run(
        [f"cat /sys/block/{device}/queue/rotational"],
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if process.stderr != "":
        raise Exception(f"Recieved error running call:\n{process.stderr}")
    if "0" in process.stdout:
        return "SSD"
    else:
        return "HDD"

def get_size(bytes, suffix="B"):
    """
    Scale bytes to its proper format
    e.g:
        1253656 => '1.20MB'
        1253656678 => '1.17GB'
    """
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

def get_host_information() -> Host:
    uname = platform.uname()
    os_info = distro.info()

    return Host(
        name=uname.node,
        os=os_info["id"],
        version=os_info["version"],
        kernel=uname.release,
        virtual=True if hasattr(sys, 'real_prefix') else False
    )

def get_cpu_information() -> CPUSummary:
    # Figure out how to get all cpus if there are mulitple
    cpu_info = cpuinfo.get_cpu_info()
    arch = cpu_info["arch_string_raw"]
    brand = cpu_info["brand_raw"]
    count = cpu_info["count"]

    cpu = CPU(brand, count, arch)
    c = CPUSummary(cores=count, sockets=1, cpus=[cpu])

    return c

def get_memory_information() -> Memory:
    return Memory(psutil.virtual_memory().total)

def get_swap_information() -> Memory:
    return Memory(psutil.swap_memory().total)

def get_partition_info(partition) -> Partition:
    return Partition(
        name=partition.get("name"),
        size=int(partition.get("size", 0)),
        mount=partition.get("mountpoint", None),
        type=partition.get("fstype")
    )

def check_for_child_partitions(d) -> List[Partition]:
    partitions = []
    if len(d.get("children", [])) != 0:
        for partition in d["children"]:
            ps = check_for_child_partitions(partition)
            partitions.extend(ps)
    if d.get("mountpoint", "") != "":
        p = get_partition_info(d)
        partitions.append(p)
    return partitions

def get_network_info() -> Network:
    if_addrs = psutil.net_if_addrs()

    ip_addresses = IpAddressesSummary([], [])

    nics: List[NIC] = []
    for interface_name, interface_addresses in if_addrs.items():
        nic = {"name": interface_name}
        name = interface_name
        ipv4 = None
        ipv6: List[str] = []
        mac = None
        for address in interface_addresses:
            if str(address.family) == 'AddressFamily.AF_INET':
                ipv4 = IpV4Address(address.address, None, address.netmask, address.broadcast, False)
                ip_addresses.ipv4.append(ipv4)
                ipv4 = address.address

            if str(address.family) == 'AddressFamily.AF_INET6':
                if "fe80::" in address.address:
                    ipv6_addr = IpV6Address(address.address.split("%")[0], None, address.netmask, address.broadcast, "LinkLocal")
                    ip_addresses.ipv6.append(ipv6_addr)
                    ipv6.append(address.address)
                else:
                    ipv6_addr = IpV6Address(address.address, None, address.netmask, address.broadcast, "Global")
                    ip_addresses.ipv6.append(ipv6_addr)
                    ipv6.append(address.address)
            elif str(address.family) == 'AddressFamily.AF_PACKET':
                nic["mac"] = address.address
        nic = NIC(name, ipv4=ipv4, ipv6=ipv6, mac=mac)
        nics.append(nic)

    return Network(ip_addresses, nics)

def get_partitions() -> Dict[str, Partition]:
    results = []
    partitions = psutil.disk_partitions()
    for partition in partitions:
        if partition.fstype == "squashfs":
            continue
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
        except PermissionError:
            continue
        name = partition.device.replace("/dev/", "")
        p = Partition(
            name=name,
            size=partition_usage.total,
            mount=partition.mountpoint,
            fstype=partition.fstype,
        )
        results.append(p)

    return results


def run_mdadm(device: str) -> str:
    process = subprocess.run(
        [f"sudo mdadm --detail /dev/{device}"],
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if process.stderr != "":
        raise Exception(f"Recieved error running call:\n{process.stderr}")
    return process.stdout

def get_raid_info() -> List[Raid]:
    raids = []
    raids_info = mdstat.parse()
    for device in raids_info["devices"].keys():
        raid_info = jc.parse('mdadm', run_mdadm(device))
        raid = build_raid(raid_info)
        raids.append(raid)
    return raids

def get_disk_info() -> List[Disk]:
    disks_info = run_lshw()
    disks = []
    for disk_info in disks_info:
        if disk_info["id"] != "medium":
            disk = build_disk(disk_info)
            disks.append(disk)
    return disks

def get_storage_info() -> Storage:
    disks, partitions, raid = None, None, None
    try:
        disks = get_disk_info()
    except Exception as e:
        print(f"Error getting disk info: {e}")
    try:
        partitions = get_partitions()
    except Exception as e:
        print(f"Error getting partition info: {e}")
    try:
        raid = get_raid_info()
    except Exception as e:
        print(f"Error getting raid info: {e}")

    return Storage(partitions, disks, raid)

def get_children(item: dict) -> List[str]:
    results = []
    for child in item.get("children", []):
        if child.get("name"):
            results.append(child["name"])
            if len(child.get("children", [])) != 0:
                children = get_children(child)
                results.extend(children)
    return results
        

def build_disk(disk: dict) -> Disk:
    name = disk.get("logicalname", str).replace("/dev/", "")
    return Disk(
        name=name,
        type=device_type(name),
        size=int(disk.get("size", 0)),
        model=disk.get("product", None),
        vendor=disk.get("vendor", None),
        serial_number=disk.get("serial", None),
        transport=transport_type(name),
    )

def build_partition(partition: dict) -> Partition:
    return Partition(
        name=partition.get("name", None),
        size=int(partition.get("size", 0)),
        mount=partition.get("mountpoint", None),
        fstype=partition.get("fstype", None),
        subpartitions=get_children(partition)
    )

def build_raid(raid: dict) -> Raid:
    name = raid.get("device", str).replace("/dev/", "")
    disks = []
    for device in raid["device_table"]:
        disks.append(device["device"].replace("/dev/", ""))

    return Raid(
        disks=disks,
        name=name,
        size=int(raid.get("array_size_num", 0)),
        type=raid.get("raid_level", None),
    )

def main():
    cpus = get_cpu_information()
    host = get_host_information()
    memory = get_memory_information()
    swap = get_swap_information()
    storage = get_storage_info()
    network = get_network_info()

    machine = Machine(cpus, host, memory, swap, storage, network)
    json_output = json.dumps(machine, indent=4, sort_keys=True, cls=EnhancedJSONEncoder)
    output = underscore_to_camel(json_output)
    print(output)
    print(base64.b64encode(output.encode()).decode())

main()