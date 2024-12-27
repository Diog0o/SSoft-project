from Types.Label import Label
from Types.MultiLabel import MultiLabel
from Types.Pattern import Pattern

class Policy:
    def __init__(self, patterns: list[Pattern]):
        self.patterns = patterns

    def get_sources_by_name(self, name: str):
        return [pattern.name for pattern in self.patterns if pattern.is_source(name)]
    
    def get_pattern_by_name(self, name: str) -> Pattern | None:
        for pattern in self.patterns:
            if pattern.name == name: return pattern
        return None

    def get_sanitizers_by_name(self, name: str):
        return [pattern.name for pattern in self.patterns if pattern.is_sanitizer(name)]

    def determine_illegal_flows(self, sink_name: str, multilabel: MultiLabel) -> MultiLabel | None:
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
                    illegal_multilabel.add_label(pattern.name, pattern_label.deep_copy())

        return None if len(illegal_multilabel.labels.keys()) == 0 else illegal_multilabel