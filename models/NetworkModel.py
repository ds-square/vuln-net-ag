class CPE:
  def __init__(self, id, name, lastModified, created, titles):
    self.id = id
    self.name = name
    self.lastModified = lastModified
    self.created = created
    self.titles = titles

class Service:
  def __init__(self, name, cpe_list, cve_list):
    self.name = name
    self.cpe_list = cpe_list
    self.cve_list = cve_list

class Port:
  def __init__(self, number, state, protocol, services):
    self.number = number
    self.state = state
    self.protocol = protocol
    self.services = services

class NetworkInterface:
  def __init__(self, ipaddress, macaddress, ports):
    self.ipaddress = ipaddress
    self.macaddress = macaddress
    self.ports = ports

class Host:
  def __init__(self, ipaddress, macaddress, applications):
    self.ipaddress = ipaddress
    self.macaddress = macaddress
    self.applications = applications