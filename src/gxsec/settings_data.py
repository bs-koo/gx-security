"""Parse bounded configuration data without resolving aliases or executing tags."""
import yaml


class SettingsLoader(yaml.BaseLoader):
    """Keep scalars as text, including GitHub Actions' `on` key."""

    def __init__(self, stream):
        super().__init__(stream)
        self.depth = 0
        self.nodes = 0

    def compose_node(self, parent, index):
        self.depth += 1
        self.nodes += 1
        if self.depth > 40 or self.nodes > 16000 or self.check_event(yaml.AliasEvent):
            raise ValueError('Unsupported YAML structure')
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result or key == '<<':
                raise ValueError('Unsupported YAML mapping key')
            result[key] = self.construct_object(value_node, deep=deep)
        return result
