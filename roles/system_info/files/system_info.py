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
# import pySMART
from blkinfo import BlkDiskInfo
import subprocess
import re
import base64

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
    arch: str

@dataclass
class Host:
    uuid: str
    name: str
    os: str
    version: str
    kernel: str
    uuid: str
    virtual: bool

@dataclass
class Memory:
    total: int

@dataclass
class Partition:
    name: str
    size: int
    mount: str
    type: str

@dataclass
class Disk:
    name: str
    partitions: List[Partition] = None
    type: Optional[str] = None
    serial_number: Optional[str] = None
    size: Optional[int] = 0
    model: Optional[str] = None
    vendor: Optional[str] = None
    controller: Optional[str] = None

@dataclass
class NIC:
    name: str
    mac: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    ipv6_local: Optional[str] = None

@dataclass
class Machine:
    """Machine"""
    id: str
    cpus: List[CPU]
    host: Host
    memory: Memory
    swap: Memory
    disks: List[Disk]
    nics: List[NIC]

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

def get_machine_id() -> str:
    process = subprocess.run(
        ["cat /etc/machine-id"],
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if process.stderr != "":
        raise Exception(f"Recieved error running call:\n{process.stderr}")
    return process.stdout.strip()

def is_rotational(dev: str) -> bool:
    process = subprocess.run(
        [f"cat /sys/block/{dev}/queue/rotational"],
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if process.stderr != "":
        raise Exception(f"Recieved error running call:\n{process.stderr}")
    if process.stdout.strip() == "0":
        return False
    return True

def get_host_information() -> Host:
    uname = platform.uname()
    os_info = distro.info()

    return Host(
        uuid=get_machine_id(),
        name=uname.node,
        os=os_info["id"],
        version=os_info["version"],
        kernel=uname.release,
        virtual=True if hasattr(sys, 'real_prefix') else False
    )

def get_cpu_information() -> List[CPU]:
    # Figure out how to get all cpus if there are mulitple
    cpu_info = cpuinfo.get_cpu_info()
    arch = cpu_info["arch_string_raw"]
    brand = cpu_info["brand_raw"]
    count = cpu_info["count"]

    c = CPU(brand, count, arch)
    return [c]

def get_memory_information() -> Memory:
    return Memory(psutil.virtual_memory().total)

def get_swap_information() -> Memory:
    return Memory(psutil.swap_memory().total)

def build_identifier() -> str:
    id = get_machine_id()
    return f"m-{id}"

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

def get_nics_info() -> List[NIC]:
    if_addrs = psutil.net_if_addrs()

    nics = []
    for interface_name, interface_addresses in if_addrs.items():
        nic = {"name": interface_name}
        for address in interface_addresses:
            if str(address.family) == 'AddressFamily.AF_INET':
                nic["ipv4"] = address.address
            if str(address.family) == 'AddressFamily.AF_INET6':
                if "fe80::" in address.address:
                    nic["ipv6_local"] = address.address.split("%")[0]
                else:
                    nic["ipv6"] = address.address
            elif str(address.family) == 'AddressFamily.AF_PACKET':
                nic["mac"] = address.address
        nic = NIC(**nic)
        nics.append(nic)
    return nics

def get_disk_info() -> List[Disk]:
    myblkd = BlkDiskInfo()
    all_disks = myblkd.get_disks()
    disk_info = run_lshw()

    disks: Dict[str, Disk] = {}

    for disk in disk_info:
        if disk.get("logicalname", None):
            name = disk["logicalname"].split("/")[2]
            if name in disks:
                continue
            d = Disk(
                name=name,
                type="HDD" if is_rotational(name) else "SSD",
                serial_number=disk.get("serial", None),
                size=int(disk.get("size", 0)),
                controller=disk.get("businfo", "@").split("@")[0],
                model=disk.get("product", None),
                vendor=disk.get("vendor", None),
            )
            disks[name] = d

    for disk in all_disks:
        partitions = check_for_child_partitions(disk)
        # remove duplicates
        partitions = [partitions[i] for i in range(len(partitions)) if i == partitions.index(partitions[i]) ]
        if disk.get("name", None):
            name = disk["name"]
            if disks.get(disk["name"]):
                disks[name].partitions = partitions
                if disks[name].type == None:
                    disks[name].type = "SSD" if disk["rota"] == "0" else "HDD"
                if disks[name].serial_number == None:
                    disks[name].serial_number = disk.get("serial", None)
                if disks[name].size == None:
                    disks[name].size = int(disk.get("size", 0))
                if disks[name].vendor == None:
                    disks[name].vendor = disk.get("vendor", None)
                if disks[name].model == None:
                    disks[name].model = disk.get("model", None)
            else:
                if disk.get("type") == "raid1":
                    for parent in disk.get("parents", []):
                        if disks.get(parent, None):
                            disks[parent].partitions = partitions

    return list(disks.values())

def main():
    cpus = get_cpu_information()
    host = get_host_information()
    memory = get_memory_information()
    swap = get_swap_information()
    id = build_identifier()
    disks = get_disk_info()
    nics = get_nics_info()


    machine = Machine(id, cpus, host, memory, swap, disks, nics)
    json_output = json.dumps(machine, indent=4, sort_keys=True, cls=EnhancedJSONEncoder)
    output = underscore_to_camel(json_output)
    print(base64.b64encode(output.encode()).decode())

main()