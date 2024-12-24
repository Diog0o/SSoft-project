from Types.Label import Label
from Types.Pattern import Pattern

class MultiLabel:
  '''
    A class to manage multiple labels, each corresponding to a specific vulnerability pattern.

    Attributes:
        labels (Dict[str, Label]): A dictionary mapping pattern names to their respective Label objects.
        patterns (Dict[str, Pattern]): A dictionary mapping pattern names to their respective Pattern objects.
    '''
  
  def __init__(self, patterns: list[Pattern]):
    '''
    Constructor for the MultiLabel class.

    :param patterns: List of Pattern objects (list of Pattern objects)
    '''
    self.labels: dict[str, Label] = {}
    for pattern in patterns:
      self.labels[pattern.get_vulnerability_name()] = Label()

    self.patterns: dict[str, Pattern] = {}
    for pattern in patterns:
      self.patterns[pattern.get_vulnerability_name()] = pattern


  def add_label_to_pattern(self, pattern_name: str, label: Label):
    self.labels[pattern_name] = label

  def update_label_of_pattern(self, pattern_name: str, label: Label, is_implicit: bool):
    if is_implicit:
      if self.patterns[pattern_name].implicit:
        self.add_label_to_pattern(pattern_name, label)
    else:
      self.add_label_to_pattern(pattern_name, label)

  def add_source_to_pattern(self, pattern_name: str, source: str, line_number: int):
    self.labels[pattern_name].add_source(source, line_number)

  def add_sorce_to_all_patterns(self, source: str, line_number: int):
    for pattern in self.patterns:
      self.add_source_to_pattern(pattern, source, line_number)

  def add_sanitizer_to_pattern(self, pattern_name: str, sanitizer: str, line_number: int):
    if pattern_name in self.labels:
      self.labels[pattern_name].add_sanitizer(sanitizer, line_number)

  def convert_implicit(self):
    for pattern_name, label in self.labels.items():
      if not self.patterns[pattern_name].implicit:
        # Reset Labels for {patterns} that don't want to include implicit flows
        self.labels[pattern_name] = Label()


  def get_sources_of_pattern (self, pattern_name: str):
    if pattern_name in self.labels:
      return self.labels[pattern_name].get_sources()
    else:
      return set()
    
  def deep_copy(self):
    copy_multilabel = MultiLabel(list(self.patterns.values()))
    for pattern_name, label in self.labels.items():
      copy_multilabel.labels[pattern_name] = label.deep_copy()
    return copy_multilabel

  def combine_multilabel(self, other_multilabel: "MultiLabel"):
    combined_multilabel: MultiLabel = other_multilabel.deep_copy()
    for pattern_name, label in self.labels.items():
        combined_multilabel.labels[pattern_name] = label.combine_labels(other_multilabel.labels[pattern_name])

    return combined_multilabel
