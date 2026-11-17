"""Converts Nmap XML into plain Python dictionaries."""
import xml.etree.ElementTree as ET


def parse_xml(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        addr_el = h.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = h.find("address")
        name_el = h.find("hostnames/hostname")
        os_el = h.find("os/osmatch")
        ports = []
        for p in h.findall("ports/port"):
            state = p.find("state")
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")),
                "protocol": p.get("protocol"),
                "state": state.get("state") if state is not None else "unknown",
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "scripts": [{"id": s.get("id"), "output": s.get("output", "")}
                            for s in p.findall("script")],
            })
        hosts.append({
            "ip": addr_el.get("addr") if addr_el is not None else "?",
            "hostname": name_el.get("name") if name_el is not None else "",
            "status": status.get("state") if status is not None else "unknown",
            "os": os_el.get("name") if os_el is not None else "",
            "ports": ports,
        })
    return {"nmap_version": root.get("version", ""), "args": root.get("args", ""), "hosts": hosts}
