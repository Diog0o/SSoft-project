from typing import List
from Types.Pattern import Pattern
from Types.MultiLabel import MultiLabel


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



    #Isto pode muito bem tar mal. VERIFICAR
    def detect_illegal_flows(self, sink_name: str, multilabel: MultiLabel) -> MultiLabel:
        """
        Given a sink name and a MultiLabel, detects illegal flows.

        :param sink_name: The sink name being analyzed.
        :param multilabel: A MultiLabel object describing the information flowing to the sink.
        :return: A new MultiLabel containing only the illegal flows for the given sink.
        """
        # Create a new MultiLabel for the illegal flows
        illegal_multilabel = MultiLabel(self.patterns)

        for pattern_name, label in multilabel.labels.items():
            # Get the pattern associated with the current label
            pattern = multilabel.patterns[pattern_name]

            # Check if the pattern recognizes the sink
            if pattern.is_sink(sink_name):
                if len(pattern.get_sources()) > 0:
                    illegal_multilabel.add_label_to_pattern(pattern_name, label.deep_copy())
        if len(illegal_multilabel.labels) == 0:
            return None
        return illegal_multilabel
