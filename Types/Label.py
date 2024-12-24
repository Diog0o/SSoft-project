
import copy


class Label:
    '''
    Track the {sources} and {sanitizers} that influenced a variable

    a = dang         {a} label = { (dang, 1): [] }
    b = dang         {b} label = { (dang, 1): [] }
    b = san(b)       {b} label = { (dang, 1): [[("san", 1)]] }
    c = a + b        {c} label = { (dang, 1): [[("san", 1)], []] }
    INTERSECTION
    Drawback: 
        In the end, there is no way to know which sources were neutralized by which sanitizers,
        only the sanitizers that were applied to the variable along the information flow 
    '''
    def __init__(self, sources_w_sanitizers: dict[tuple[str, int], list[set[tuple[str, int]]]] = { }):
        self._sources_w_sanitizers = copy.deepcopy(sources_w_sanitizers)

    def add_source(self, source):
        # If source already exists resets its sanitization paths
        self._sources_w_sanitizers[source] = list()
        # adds 1 unsanitized path
        self._sources_w_sanitizers[source].append(set())

    def add_sanitizer(self, sanitizer: str, line_number: int):
        '''
        Sanitizes all sources of this Label

        sources_n_sanitizers => { ("a", 1): [ [("san1", 1), ("san2", 2)], [("san3", 2)], [] ] }
        add_sanitizer("san4")
        sources_n_sanitizers => { ("a", 1): [ [("san1", 1), ("san2", 2), ("san4", 1)], [("san3", 2), ("san4", 1)], [("san4", 1)] ] }
        '''
        for source in self.get_sources():
            for sanitization_paths in self._sources_w_sanitizers[source]:
                sanitization_paths.add((sanitizer, line_number))

    def get_sources(self):
        return self._sources_w_sanitizers.keys()
    
    def get_source_sanitizers(self, source: str, line_number: int) -> list[set[tuple[str, int]]]:
        return self._sources_w_sanitizers[(source, line_number)]
    
    def get_sources_and_sanitizers(self):
        return self._sources_w_sanitizers

    def deep_copy(self):
        clonedLabel = Label()
        for source, original_sanitization_flows in self._sources_w_sanitizers.items():
            sanitization_flows: list[set[tuple[str, int]]] = list()
            for original_sanitization_flow in original_sanitization_flows:
                sanitization_flow: set[tuple[str, int]] = set()
                for original_sanitizer in original_sanitization_flow:
                    sanitization_flow.add((original_sanitizer[0], original_sanitizer[1]))
                sanitization_flows.append(sanitization_flow)
            clonedLabel._sources_w_sanitizers[source] = sanitization_flows
        return clonedLabel

    def combine(self, other_label: "Label") -> "Label":
        mergedSourcesAndSanitizers: dict[tuple[str, int], list[set[tuple[str, int]]]] = {}
        
        for source in list(self.get_sources_and_sanitizers()) + list(other_label.get_sources_and_sanitizers()):
            if source in self.get_sources_and_sanitizers() and source in other_label.get_sources_and_sanitizers():
                '''
                self => { ("a", 1): [ [("san1", 1), ("san2", 2)], [("san3", 2)], [] ] }
                other => { ("a", 1): [ [("san3", 2)], [] ] }
                combined => { ("a", 1): [ [("san1", 1), ("san2", 2)], [("san3", 2)], [], [("san3", 2)], [] ] }
                    just merge lists, removing duplicates
                '''
                mergedSourcesAndSanitizers[source] = self.get_source_sanitizers(source[0], source[1]) + other_label.get_source_sanitizers(source[0], source[1])
                # Remove duplicates
                for san_path in mergedSourcesAndSanitizers[source]:
                    if mergedSourcesAndSanitizers[source].count(san_path) > 1:
                        mergedSourcesAndSanitizers[source].remove(san_path)
            elif source in self.get_sources_and_sanitizers():
                # not in {other}
                mergedSourcesAndSanitizers[source] = self.get_source_sanitizers(source[0], source[1])
            elif source in other_label.get_sources_and_sanitizers():
                # not in {self}
                mergedSourcesAndSanitizers[source] = other_label.get_source_sanitizers(source[0], source[1])

        return Label(mergedSourcesAndSanitizers)