class Pattern:
    def __init__(self, vulnerability_name: str, sources: list[str], sanitizers: list[str], sinks: list[str], implicit: str ):
        """
        Constructor for the Pattern class.

        :param vulnerability_name: Name of the vulnerability pattern (string)
        :param sources: List of possible source names (list of strings)
        :param sanitizers: List of possible sanitizer names (list of strings)
        :param sinks: List of possible sink names (list of strings)
        """
        self.vulnerability_name = vulnerability_name
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks
        if implicit == "yes":
            self.implicit = True
        else:
            self.implicit = False

    def get_vulnerability_name(self):
        return self.vulnerability_name

    def get_sources(self):
        return self.sources

    def get_sanitizers(self):
        return self.sanitizers

    def get_sinks(self):
        return self.sinks

    def is_source(self, name):
        return name in self.sources

    def is_sanitizer(self, name):
        return name in self.sanitizers

    def is_sink(self, name):
        return name in self.sinks