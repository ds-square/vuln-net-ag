class Condition:
  def __init__(self, CVE, CPE, accessRequired, requiredInteraction, acInsufInfo, gainRoot, gainUser, gainOther):
    self.CVE = CVE
    self.CPE = CPE
    self.accessRequired = accessRequired
    self.requiredInteraction = requiredInteraction
    self.acInsufInfo = acInsufInfo
    self.gainRoot = gainRoot
    self.gainUser = gainUser
    self.gainOther = gainOther

class MetricV2:
  def __init__(self, vectorString, accessVector, accessComplexity, authentication,
               confidentiality, integrity, availability, score, severity, 
               exploitability, impact):
    self.vectorString = vectorString
    self.accessVector = accessVector
    self.accessComplexity = accessComplexity
    self.authentication = authentication
    self.confidentiality = confidentiality
    self.integrity = integrity
    self.availability = availability
    self.score = score
    self.severity = severity
    self.exploitability = exploitability
    self.impact = impact

class MetricV3:
  def __init__(self, vectorString, attackVector, attackComplexity, privilegeRequired,
               userInteraction, scope, confidentiality, integrity, availability, 
               score, severity, exploitability, impact):
    self.vectorString = vectorString
    self.attackVector = attackVector
    self.attackComplexity = attackComplexity
    self.privilegeRequired = privilegeRequired
    self.userInteraction = userInteraction
    self.scope = scope,
    self.confidentiality = confidentiality
    self.integrity = integrity
    self.availability = availability
    self.score = score
    self.severity = severity
    self.exploitability = exploitability
    self.impact = impact    

class CVE:
  def __init__(self, id, created, lastModified, status, description, metricV2, metricV3, condition, configuration):
    self.id = id
    self.created = created
    self.lastModified = lastModified
    self.status = status
    self.description = description
    self.metricV2 = metricV2
    self.metricV3 = metricV3
    self.condition = condition
    self.configuration = configuration

  def get_dict_cve(self):
    return {
      "_id": self.id,
      "created": self.created,
      "lastModified": self.lastModified,
      "status": self.status,
      "description": self.description,
      "metricV2": self.metricV2.__dict__ if self.metricV2 else None,
      "metricV3": self.metricV3.__dict__ if self.metricV3 else None,
      "condition": self.condition.__dict__,
      # "configuration": self.configuration
      }