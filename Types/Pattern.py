
class Pattern:
    def __init__(self, vulnerability: str, sources: list[str], sanitizers: list[str], sinks: list[str], implicit: str):
        self.name = vulnerability
        self.sources = set(sources)
        self.sanitizers = set(sanitizers)
        self.sinks = set(sinks)
        self.implicit = implicit == "yes"

    def is_source(self, name: str) -> bool: return name in self.sources
    def is_sink(self, name: str) -> bool: return name in self.sinks
    def is_sanitizer(self, name: str) -> bool: return name in self.sanitizers