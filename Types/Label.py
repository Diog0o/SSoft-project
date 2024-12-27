import copy

class Label:
    '''
    Represents a label that tracks sources and their associated sanitizers.
    Dictionary of sources and their sanitizers:
    sources_n_sanitizers => { ("a", 1): [ [("san1", 1), ("san2", 2)], [("san3", 2)], [] ] }
    '''
    def __init__(self, sources_w_sanitizers: dict[tuple[str, int], list[set[tuple[str, int]]]] = {}, is_implicit: bool = False):
        self._sources_sanitizers_dict = copy.deepcopy(sources_w_sanitizers)
        self._is_implicit = is_implicit

    def set_implicit(self, implicit: bool):
        self._is_implicit = implicit

    def is_implicit(self) -> bool:
        return self._is_implicit
    
    def add_sanitizer(self, sanitizer: str, line_number: int):
        for source in self.get_sources():
            for sanitization_paths in self._sources_sanitizers_dict[source]:
                sanitization_paths.add((sanitizer, line_number))

    def add_source(self, source):
        self._sources_sanitizers_dict[source] = list()
        self._sources_sanitizers_dict[source].append(set())

    
    def get_sources(self):
        return self._sources_sanitizers_dict.keys()
    
    def get_sanitizers_of_source(self, source: str, line_number: int) -> list[set[tuple[str, int]]]:
        return self._sources_sanitizers_dict[(source, line_number)]
    
    def get_sources_and_sanitizers(self):
        return self._sources_sanitizers_dict

    def deep_copy(self):
        clonedLabel = Label()
        clonedLabel._is_implicit = self._is_implicit
        for source, original_sanitization_flows in self._sources_sanitizers_dict.items():
            sanitization_flows: list[set[tuple[str, int]]] = list()
            for original_sanitization_flow in original_sanitization_flows:
                sanitization_flow: set[tuple[str, int]] = set()
                for original_sanitizer in original_sanitization_flow:
                    sanitization_flow.add((original_sanitizer[0], original_sanitizer[1]))
                sanitization_flows.append(sanitization_flow)
            clonedLabel._sources_sanitizers_dict[source] = sanitization_flows
        return clonedLabel

    def combine(self, other_label: "Label") -> "Label":
        mergedSourcesAndSanitizers: dict[tuple[str, int], list[set[tuple[str, int]]]] = {}
        
        for source in list(self.get_sources_and_sanitizers()) + list(other_label.get_sources_and_sanitizers()):
            if source in self.get_sources_and_sanitizers() and source in other_label.get_sources_and_sanitizers():
                mergedSourcesAndSanitizers[source] = self.get_sanitizers_of_source(source[0], source[1]) + other_label.get_sanitizers_of_source(source[0], source[1])
                # Remove duplicates
                for san_path in mergedSourcesAndSanitizers[source]:
                    if mergedSourcesAndSanitizers[source].count(san_path) > 1:
                        mergedSourcesAndSanitizers[source].remove(san_path)
            elif source in self.get_sources_and_sanitizers():
                mergedSourcesAndSanitizers[source] = self.get_sanitizers_of_source(source[0], source[1])
            elif source in other_label.get_sources_and_sanitizers():
                mergedSourcesAndSanitizers[source] = other_label.get_sanitizers_of_source(source[0], source[1])

        combined_label = Label(mergedSourcesAndSanitizers)
        # Set implicit if either label is implicit
        combined_label.set_implicit(self.is_implicit() or other_label.is_implicit())
        return combined_label