from Types.MultiLabel import MultiLabel

class MultiLabelling:
  '''
  labels: dict[str, MultiLabel] - A dictionary that maps variable names to MultiLabel objects.
  variable_names: set[str] - A set containing the names of the variables that are defined in the program.
  '''
  def __init__(self):
    self.labels: dict[str, MultiLabel] = {}
    # Names which are defined in the program (even if have constant values)
    self.variable_names: set[str] = set()

  def is_variable_defined (self, variable_name: str) -> bool:
    return variable_name in self.variable_names
  
  def add_variable_name (self, variable_name: str):
    self.variable_names.add(variable_name)

  def get_multilabel_by_variable_name (self, variable_name: str) -> MultiLabel | None:
    return self.labels.get(variable_name, None)
  
  def update_multilabel_by_variable_name (self, variable_name: str, multilabel: MultiLabel):
    self.labels[variable_name] = multilabel
    if not self.is_variable_defined(variable_name):
      self.add_variable_name(variable_name)

  def add_sanitizer(self, pattern_name, sanitizer: str, line_number: int):
    if pattern_name in self.labels:
        self.labels[pattern_name].add_sanitizer_to_pattern(sanitizer, line_number)
  
  def add_source(self, pattern_name: str, source: str, line_number: int):
      self.labels[pattern_name].add_source_to_pattern((source, line_number))

      # To use when an undefined {name} impacts a MultiLabel
  def add_source_to_all(self, source: str, line_number: int):
      for pattern_name in self.labels.keys():
          self.labels[pattern_name].add_sorce_to_all_patterns((source, line_number))
          
  def deep_copy(self):
    copy_multilabelling = MultiLabelling()
    for varname, multilabel in self.labels.items():
      copy_multilabelling.labels[varname] = multilabel.deep_copy()
    for defined_name in self.variable_names:
      copy_multilabelling.add_variable_name(defined_name)
    return copy_multilabelling

  def update_multilabel_for_name(self, name: str, multilabel: MultiLabel):
    self.labels[name] = multilabel

    if not self.is_variable_defined(name):
        self.add_variable_name(name)

  def change (self, other_multi_labelling: "MultiLabelling"):
    self.labels = other_multi_labelling.labels
    self.variable_names = other_multi_labelling.variable_names



  def combine (self, other_multi_labelling: "MultiLabelling", are_alternative_branches: bool = False):
    '''
    Combines two MultiLabelling objects into one.
    are_alternative_branches: bool - True if objects represent alternative branches of execution, False otherwise.
    '''
    if are_alternative_branches:
      self.variable_names = self.variable_names.intersection(other_multi_labelling.variable_names)
    else:
      self.variable_names = self.variable_names.union(other_multi_labelling.variable_names)

    for varname in list(other_multi_labelling.labels.keys()) + list(self.labels.keys()):
      # Both MultiLabelling objects have a MultiLabel for the variable
      if varname in self.labels and varname in other_multi_labelling.labels:
        self.labels[varname].combine_multilabel(other_multi_labelling.labels[varname])
      #Only self.labels has a MultiLabel for the variable
      elif varname in self.labels:
        if varname not in self.variable_names:
          self.labels[varname].add_sorce_to_all_patterns(varname, -1)
      # Only other_multi_labelling.labels has a MultiLabel for the variable
      elif varname in other_multi_labelling.labels:
        self.labels[varname] = other_multi_labelling.labels[varname]
        if varname not in self.variable_names:
          other_multi_labelling.labels[varname].add_sorce_to_all_patterns(varname, -1)
    return None
  
  