from typing import List
from Types.Pattern import Pattern
from Types.MultiLabel import MultiLabel, Label


class Policy:
    '''
    Represents an information flow policy that uses a pattern database to recognize illegal flows.

    Attributes:
        patterns (list[Pattern]): A list of vulnerability patterns to be considered.
    '''

    def __init__(self, patterns: List[Pattern]):
        self.patterns = patterns

    def get_vulnerability_names(self) -> List[str]:
        return [pattern.get_vulnerability_name() for pattern in self.patterns]

    def get_vulnerabilities_with_source(self, source_name: str) -> List[str]:
        return [pattern.get_vulnerability_name() for pattern in self.patterns if pattern.is_source(source_name)]

    def get_vulnerabilities_with_sanitizer(self, sanitizer_name: str) -> List[str]:
        return [pattern.get_vulnerability_name() for pattern in self.patterns if pattern.is_sanitizer(sanitizer_name)]

    def get_vulnerabilities_with_sink(self, sink_name: str) -> List[str]:
        return [pattern.get_vulnerability_name() for pattern in self.patterns if pattern.is_sink(sink_name)]

    def get_pattern_by_name(self, vulnerability_name: str) -> Pattern | None:
        for pattern in self.patterns:
            if pattern.get_vulnerability_name == vulnerability_name: return pattern
        return None
 
    # #Isto pode muito bem tar mal. VERIFICAR
    # def detect_illegal_flows(self, sink_name: str, multilabel: MultiLabel) -> MultiLabel:
    #     """
    #     Given a sink name and a MultiLabel, detects illegal flows.

    #     :param sink_name: The sink name being analyzed.
    #     :param multilabel: A MultiLabel object describing the information flowing to the sink.
    #     :return: A new MultiLabel containing only the illegal flows for the given sink.
    #     """
    #     # Create a new MultiLabel for the illegal flows
    #     illegal_multilabel = MultiLabel(self.patterns)

    #     for pattern_name, label in multilabel.labels.items():
    #         # Get the pattern associated with the current label
    #         pattern = multilabel.patterns[pattern_name]

    #         # Check if the pattern recognizes the sink
    #         if pattern.is_sink(sink_name) and len(pattern.get_sources()) > 0:
    #             if len(pattern.get_sources()) > 0:
    #                 illegal_multilabel.add_label_to_pattern(pattern_name, label.deep_copy())
    #     if len(illegal_multilabel.labels) == 0:
    #         return None
    #     return illegal_multilabel

    def detect_illegal_flows(self, sink_name: str, multilabel: MultiLabel) -> MultiLabel | None:
        illegal_multilabel = MultiLabel(self.patterns)

        '''
        For each pattern for which the multilabel has a label:
            if {sink_name} is a sink for that pattern AND that Label has >= 1 source:
                {illegal_multilabel}.{pattern_name}.add_sources(label_sources)
                {illegal_multilabel}.{pattern_name}.add_sanitizers(label_sanitizers)
        '''
        for pattern_name in multilabel.labels.keys():
            pattern: Pattern | None = self.get_pattern_by_name(pattern_name)
            if not pattern: continue

            pattern_label: Label = multilabel.labels[pattern_name]
            # Ex: sink_name = a.b
            for sink in sink_name.split("."):
                if pattern.is_sink(sink) and len(pattern_label.get_sources()) > 0:
                    illegal_multilabel.add_label_to_pattern(pattern.get_vulnerability_name, pattern_label.deep_copy())

        return None if len(illegal_multilabel.labels.keys()) == 0 else illegal_multilabel