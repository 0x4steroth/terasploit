"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/pex/parser/graphml.py
"""

import xml.sax
import xml.sax.handler


class GraphMLError(Exception):
    """Base error class for all GraphML parsing exceptions."""


class ParserError(GraphMLError):
    """Raised when structural or hierarchical issues occur during XML processing."""


class InvalidAttributeError(ParserError):
    """Raised when an XML attribute is missing, duplicated, or misconfigured."""

    def __init__(self, element, attribute, details=None, missing=True):
        """Initializes the exception with descriptive structural context."""
        self.element = element
        self.attribute = attribute
        self.missing = missing
        message = f"Element '{element}' contains an invalid attribute: '{attribute}'"
        if details:
            message += f" ({details})"
        super().__init__(message)


def convert_attribute(attr_type, value):
    """
    Converts a GraphML string value into its native Python data type,
    supporting hex notation for integers to match Ruby's Integer() method.
    """
    if attr_type == "boolean":
        val_strip = value.strip()
        if not val_strip:
            return False
        return val_strip.lower() != "false"
    elif attr_type in ("int", "long"):
        # Explicitly pass base=0 to parse 0x hex, 0b binary, and base-10 automatically
        return int(value.strip(), 0)
    elif attr_type in ("float", "double"):
        return float(value)
    elif attr_type == "string":
        return value
    else:
        raise ValueError(f"Unsupported attribute type: {attr_type}")


class MetaAttribute:
    """Defines global validation rules and schemas for graph data attributes."""

    def __init__(self, id_, name, type_, domain="all", default=None):
        """Initializes metadata tracking properties."""
        self.id = id_
        self.name = name
        self.type = type_
        self.domain = domain
        self.default = default

    @classmethod
    def from_key(cls, key_element):
        """Generates a MetaAttribute instance directly from a parsed Key object."""
        default_val = key_element.default.value if key_element.default else None
        return cls(
            key_element.id,
            key_element.attr_name,
            key_element.attr_type,
            domain=key_element.domain,
            default=default_val,
        )

    def convert(self, value):
        """Normalizes and typecasts incoming data elements."""
        return convert_attribute(self.type, value)

    def valid_for(self, element):
        """Determines if the attribute domain matches the specific target component type."""
        if self.domain == "all":
            return True
        return self.domain == getattr(element, "ELEMENT_NAME", None)


class AttributeContainer:
    """Base structural class allowing an entity to retain parsed properties."""

    def __init__(self):
        """Initializes internal attribute dict storage."""
        self.attributes = {}


class Data:
    """Represents an active data assignment token mapping onto parent containers."""

    ELEMENT_NAME = "data"

    def __init__(self, key):
        """Tracks the explicit lookup key constraint reference."""
        self.key = key
        self.value = None

    @classmethod
    def from_xml_attributes(cls, xml_attrs):
        """Validates entry specifications and constructs data parameters."""
        key = xml_attrs.get("key")
        if key is None:
            raise InvalidAttributeError("data", "key")
        return cls(key)


class Default:
    """Tracks generic fallback parameter defaults within a specification key block."""

    ELEMENT_NAME = "default"

    def __init__(self, value=None):
        """Initializes the inner fallback values."""
        self.value = value

    @classmethod
    def from_xml_attributes(cls, xml_attrs):
        """Constructs an empty property default wrapper."""
        return cls()


class Edge(AttributeContainer):
    """Tracks directional or non-directional block dependencies inside graphs."""

    ELEMENT_NAME = "edge"

    def __init__(self, source, target, directed, id_=None):
        """Maps relationship constraints onto execution nodes."""
        super().__init__()
        self.source = source
        self.target = target
        self.directed = directed
        self.id = id_

    @classmethod
    def from_xml_attributes(cls, xml_attrs, edgedefault):
        """Calculates direction properties using parent context defaults."""
        source = xml_attrs.get("source")
        if source is None:
            raise InvalidAttributeError("edge", "source")

        target = xml_attrs.get("target")
        if target is None:
            raise InvalidAttributeError("edge", "target")

        directed_attr = xml_attrs.get("directed")
        if directed_attr is None:
            directed = edgedefault == "directed"
        elif directed_attr in ("true", "false"):
            directed = directed_attr == "true"
        else:
            raise InvalidAttributeError(
                "edge",
                "directed",
                details="must be either true or false when specified",
                missing=False,
            )

        return cls(source, target, directed, id_=xml_attrs.get("id"))


class Graph(AttributeContainer):
    """Container managing individual nodes and associated flow edges."""

    ELEMENT_NAME = "graph"

    def __init__(self, edgedefault, id_=None):
        """Initializes node tracking tables and default direction metrics."""
        super().__init__()
        self.edgedefault = edgedefault
        self.id = id_
        self.nodes = {}
        self.edges = []

    @classmethod
    def from_xml_attributes(cls, xml_attrs):
        """Extracts configuration maps to set graph environment expectations."""
        edgedefault = xml_attrs.get("edgedefault")
        if edgedefault not in ("directed", "undirected"):
            raise InvalidAttributeError("graph", "edgedefault", missing=(edgedefault is None))
        return cls(edgedefault, id_=xml_attrs.get("id"))


class GraphML:
    """Top level document root container matching complete parsed targets."""

    ELEMENT_NAME = "graphml"

    def __init__(self):
        """Tracks globally gathered elements cross-referenced across parsers."""
        self.nodes = {}
        self.edges = []
        self.graphs = []


class Key:
    """Defines structural field layouts valid anywhere within the graph map."""

    ELEMENT_NAME = "key"

    def __init__(self, id_, name, type_, domain):
        """Tracks the validation constraint boundaries."""
        self.id = id_
        self.attr_name = name
        self.attr_type = type_
        self.domain = domain
        self.default = None

    @classmethod
    def from_xml_attributes(cls, xml_attrs):
        """Enforces schema configuration limits on incoming configuration keys."""
        id_ = xml_attrs.get("id")
        if id_ is None:
            raise InvalidAttributeError("key", "id")

        name = xml_attrs.get("attr.name")
        if name is None:
            raise InvalidAttributeError("key", "attr.name")

        type_ = xml_attrs.get("attr.type")
        if type_ not in ("boolean", "int", "long", "float", "double", "string"):
            raise InvalidAttributeError(
                "key",
                "attr.type",
                details="must be boolean int long float double or string",
                missing=(type_ is None),
            )

        domain = xml_attrs.get("for")
        if domain not in ("graph", "node", "edge", "all"):
            raise InvalidAttributeError(
                "key",
                "for",
                details="must be graph node edge or all",
                missing=(domain is None),
            )

        return cls(id_, name, type_, domain)

    def set_default(self, default_element):
        """Sets data defaults cleanly, running active parsing conversions."""
        self.default = default_element
        if self.default and self.default.value is not None:
            self.default.value = convert_attribute(self.attr_type, self.default.value)


class Node(AttributeContainer):
    """Tracks basic blocks containing metadata instructions and subgraphs."""

    ELEMENT_NAME = "node"

    def __init__(self, id_):
        """Establishes tracking fields for relational data flows."""
        super().__init__()
        self.id = id_
        self.edges = []
        self.subgraph = None

    @classmethod
    def from_xml_attributes(cls, xml_attrs):
        """Validates layout properties to confirm structural integrity."""
        id_ = xml_attrs.get("id")
        if id_ is None:
            raise InvalidAttributeError("node", "id")
        return cls(id_)

    def source_edges(self):
        """Inbound dependencies where this node functions as the destination."""
        return [edge for edge in self.edges if edge.target == self.id or not edge.directed]

    def target_edges(self):
        """Outbound branches directing executions further down the chain."""
        return [edge for edge in self.edges if edge.source == self.id or not edge.directed]


class DocumentHandler(xml.sax.handler.ContentHandler):
    """SAX event-handler cleanly re-assembling structured graph environments."""

    def __init__(self):
        """Prepares standard execution fields, buffers, and tracking stacks."""
        super().__init__()
        self.stack = []
        self.nodes = {}
        self.meta_attributes = {}
        self.graphml = None
        self._current_text = []

    def startElement(self, name, attrs):
        """Intercepts opening tags, validating structural parenting limits."""
        self._current_text = []
        # Safe extraction method bypassing standard dictionary cast vulnerabilities
        attrs_dict = {k: v for k, v in attrs.items()}

        if name == "data":
            if not self.stack or not isinstance(self.stack[-1], AttributeContainer):
                raise ParserError(
                    "The 'data' element must be a direct child of an attribute container"
                )
            element = Data.from_xml_attributes(attrs_dict)

        elif name == "default":
            if not self.stack or not isinstance(self.stack[-1], Key):
                raise ParserError("The 'default' element must be a direct child of a 'key' element")
            element = Default.from_xml_attributes(attrs_dict)

        elif name == "edge":
            if not self.stack or not isinstance(self.stack[-1], Graph):
                raise ParserError("The 'edge' element must be a direct child of a 'graph' element")
            element = Edge.from_xml_attributes(attrs_dict, self.stack[-1].edgedefault)
            self.graphml.edges.append(element)

        elif name == "graph":
            element = Graph.from_xml_attributes(attrs_dict)
            if self.stack and isinstance(self.stack[-1], Node):
                self.stack[-1].subgraph = element
            self.graphml.graphs.append(element)

        elif name == "graphml":
            if self.stack:
                raise ParserError("The 'graphml' element must be a top-level element")
            element = GraphML()
            self.graphml = element

        elif name == "key":
            if not self.stack or not isinstance(self.stack[-1], GraphML):
                raise ParserError("The 'key' element must be a direct child of a 'graphml' element")
            element = Key.from_xml_attributes(attrs_dict)
            if element.id in self.meta_attributes:
                raise InvalidAttributeError("key", "id", details="duplicate key id", missing=False)
            if any(attr.name == element.attr_name for attr in self.meta_attributes.values()):
                raise InvalidAttributeError(
                    "key",
                    "attr.name",
                    details="duplicate key attr.name",
                    missing=False,
                )

        elif name == "node":
            if not self.stack or not isinstance(self.stack[-1], Graph):
                raise ParserError("The 'node' element must be a direct child of a 'graph' element")
            element = Node.from_xml_attributes(attrs_dict)
            if element.id in self.nodes:
                raise InvalidAttributeError(
                    "node", "id", details="duplicate node id", missing=False
                )
            self.nodes[element.id] = element
            self.graphml.nodes[element.id] = element

        else:
            raise ParserError(f"Unknown element: {name}")

        self.stack.append(element)

    def characters(self, content):
        """Buffers ongoing character fragments tracking inline string text."""
        self._current_text.append(content)

    def endElement(self, name):
        """Validates attributes and properties once an XML tag block closes."""
        element = self.stack.pop()
        text_content = "".join(self._current_text)

        if isinstance(element, Data):
            parent = self.stack[-1]
            meta_attribute = self.meta_attributes.get(element.key)
            if not meta_attribute or not meta_attribute.valid_for(parent):
                name_str = meta_attribute.name if meta_attribute else element.key
                elem_name = getattr(parent, "ELEMENT_NAME", "unknown")
                raise ParserError(f"The {name_str} attribute is invalid for {elem_name} elements")

            converted_val = meta_attribute.convert(text_content)
            if (
                meta_attribute.type == "string"
                and parent.attributes.get(meta_attribute.name) is not None
            ):
                parent.attributes[meta_attribute.name] += converted_val
            else:
                parent.attributes[meta_attribute.name] = converted_val

        elif isinstance(element, Default):
            element.value = text_content

        if isinstance(element, AttributeContainer):
            self._populate_element_default_attributes(element)

        if name == "default":
            key_el = self.stack[-1]
            key_el.set_default(element)

        elif name == "edge":
            graph_el = self.stack[-1]
            graph_el.edges.append(element)

        elif name == "graph":
            for edge in element.edges:
                source_node = element.nodes.get(edge.source)
                if source_node is None:
                    raise InvalidAttributeError(
                        "edge",
                        "source",
                        details=f"undefined source: '{edge.source}'",
                        missing=False,
                    )

                target_node = element.nodes.get(edge.target)
                if target_node is None:
                    raise InvalidAttributeError(
                        "edge",
                        "target",
                        details=f"undefined target: '{edge.target}'",
                        missing=False,
                    )

                source_node.edges.append(edge)
                target_node.edges.append(edge)

        elif name == "key":
            meta_attr = MetaAttribute.from_key(element)
            self.meta_attributes[meta_attr.id] = meta_attr

        elif name == "node":
            graph_el = self.stack[-1]
            graph_el.nodes[element.id] = element

    def _populate_element_default_attributes(self, element):
        """Applies configured global schema fallback defaults onto containers."""
        for meta_attribute in self.meta_attributes.values():
            if not meta_attribute.valid_for(element):
                continue
            if meta_attribute.name in element.attributes:
                continue
            if meta_attribute.default is None:
                continue
            element.attributes[meta_attribute.name] = meta_attribute.default


def from_file(file_path):
    """Loads a target GraphML document from the filesystem.

    Args:
        file_path (str): Filepath location to pass directly to the parser.

    Returns:
        GraphML: Fully loaded graph layout.
    """
    parser = xml.sax.make_parser()
    handler = DocumentHandler()
    parser.setContentHandler(handler)

    with open(file_path, "rb") as f:
        parser.parse(f)

    return handler.graphml
