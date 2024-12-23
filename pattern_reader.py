import json
from Types.Pattern import Pattern
from Types.Policy import Policy


def read_pattern(path: str) -> Policy:
  with open(path, "r") as file:
    patterns_dict = json.loads(file.read())
  
  patterns = [
    Pattern(
      pattern["vulnerability"],
      pattern["sources"],
      pattern["sanitizers"],
      pattern["sinks"],
      pattern["implicit"]
    ) for pattern in patterns_dict
  ]
  return Policy(patterns)

