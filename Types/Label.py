class Label:
  def __init__(self, sources_and_sanitizers: dict[tuple[str, int], list[set[tuple[str, int]]]] = None):
        self.sources_and_sanitizers = sources_and_sanitizers if sources_and_sanitizers is not None else {}


  def get_sources (self):
    return self.sources_and_sanitizers.keys()
  
  def get_sanitizers_of_source (self, source: str, line_number: int):
    tuple_source = (source, line_number)
    if tuple_source in self.sources_and_sanitizers:
      return self.sources_and_sanitizers[tuple_source]
    return None
  
  def get_sources_and_sanitizers (self):
    return self.sources_and_sanitizers

  def add_source (self, source: str, line_number: int):
    source_tuple = (source, line_number)
    self.sources_and_sanitizers[source_tuple] = list()
    self.sources_and_sanitizers[source_tuple].append(set())

  def add_sanitizer (self, sanitizer: str, line_number: int ):
    sanitizer_tuple = (sanitizer, line_number)
    for sources in self.get_sources():
      for paths in self.sources_and_sanitizers[sources]:
        paths.add(sanitizer_tuple)

  def combine_labels (self, other : "Label"):
    merged_label: dict[tuple[str, int], list[set[tuple[str, int]]]] = {}
    for source in list(self.get_sources_and_sanitizers()) + list(other.get_sources_and_sanitizers()):
      if source in self.get_sources_and_sanitizers() and source in other.get_sources_and_sanitizers():
        # We have the source in both Labels so we need to merge the sanitizers removing duplicates
        merged_label[source] = self.get_sanitizers_of_source(source[0], source[1]) + other.get_sanitizers_of_source(source[0],source[1])
        for sanitizers in merged_label[source]:
          if merged_label[source].count(sanitizers) > 1:
            merged_label[source].remove(sanitizers)
      
      elif source in self.sources_and_sanitizers.keys():
        # We only have the source in the first Label
        merged_label[source] = self.get_sanitizers_of_source(source[0], source[1])
      
      elif source in other.sources_and_sanitizers.keys():
        # We only have the source in the second Label
        merged_label[source] = other.get_sanitizers_of_source(source[0], source[1])
    return Label(merged_label)
  
  def deep_copy(self):
      copyLabel = Label()
      # Call the method properly to get the dictionary
      for source, sanitization_paths in self.get_sources_and_sanitizers().items():
          copy_sanitization_paths: list[set[tuple[str, int]]] = []
          for original_sanitization_flow in sanitization_paths:
              sanitization_flow: set[tuple[str, int]] = set()
              for original_sanitizer in original_sanitization_flow:
                  sanitization_flow.add((original_sanitizer[0], original_sanitizer[1]))
              copy_sanitization_paths.append(sanitization_flow)
          # Ensure you are using the correct attribute to set values
          copyLabel.sources_and_sanitizers[source] = copy_sanitization_paths
      return copyLabel


