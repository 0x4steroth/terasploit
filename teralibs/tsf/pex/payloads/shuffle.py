"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/pex/payloads/shuffle.py
"""

import random
import re

from teralibs.tsf.pex.parser.graphml import from_file


class Shuffle:
    """Port of Metasploit Framework's Rex::Payloads::Shuffle module."""

    FLOW_INSTRUCTIONS = {}
    FLOW_INSTRUCTIONS["x86"] = [
        "call",
        "jae",
        "jb",
        "jbe",
        "jc",
        "jcxz",
        "je",
        "jecxz",
        "jg",
        "jge",
        "jl",
        "jle",
        "jmp",
        "jna",
        "jnae",
        "jnb",
        "jnbe",
        "jnc",
        "jne",
        "jng",
        "jnge",
        "jnl",
        "jnle",
        "jno",
        "jnp",
        "jns",
        "jnz",
        "jo",
        "jp",
        "jpe",
        "jpo",
        "js",
        "jz",
    ]
    FLOW_INSTRUCTIONS["x64"] = [*FLOW_INSTRUCTIONS["x86"], "jrcxz"]

    @classmethod
    def from_graphml_file(cls, file_path, arch=None, name=None):
        """
        Shuffles blocks and internal instruction chains extracted from a GraphML file.
        """
        graphml = from_file(file_path)

        raw_blocks = {
            _id: node
            for _id, node in graphml.nodes.items()
            if node.attributes.get("type") == "block"
        }

        blocks = cls._create_path(raw_blocks, graphml.graphs[0].edges)
        blocks = [{"node": block, "instructions": cls._process_block(block)} for block in blocks]

        label_prefix = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(4))

        def labeler(address):
            """Generates a structured localized position string label."""
            return f"loc_{label_prefix}{address:04x}"

        source_lines = []
        labeled = []
        label_refs = []

        for block in blocks:
            source_lines.append(f"{labeler(block['node'].attributes['address'])}:")
            labeled.append(block["node"].attributes["address"])

            instructions = []
            for node in block["instructions"]:
                src_text = node.attributes["instruction.source"].strip()

                # Check if the instruction is a relative control flow branch
                is_flow = False
                if arch in cls.FLOW_INSTRUCTIONS:
                    match = re.match(r"^(?P<mnemonic>\S+)\s+(?P<address>0x[a-f0-9]+)$", src_text)
                    if match and match.group("mnemonic") in cls.FLOW_INSTRUCTIONS[arch]:
                        is_flow = True
                        address = int(match.group("address"), 16)
                        instructions.append(f"{match.group('mnemonic')} {labeler(address)}")
                        label_refs.append(address)

                # Fallback to byte translation only for standard non-branching blocks
                if not is_flow and arch in ["x86", "x64"]:
                    hex_str = node.attributes["instruction.hex"].strip()
                    hex_bytes = [f"0x{hex_str[i : i + 2]}" for i in range(0, len(hex_str), 2)]
                    instructions.append("db " + ", ".join(hex_bytes))
                elif not is_flow:
                    instructions.append(src_text)

            for inst in instructions:
                source_lines.append(f"    {inst}")

        if not all(address in labeled for address in label_refs):
            raise Exception(
                "Missing label reference: shuffled branch points to unmapped block alignment."
            )

        if name is not None:
            source_lines = [f"{name}:"] + [" " * 16 + f"{line}" for line in source_lines]

        return "\n".join(source_lines) + "\n"

    @classmethod
    def _process_block(cls, block):
        """
        Extracts and topologically sorts instructions inside a generic basic block node wrapper.
        """
        subgraph = block.subgraph
        instructions = {
            _id: node
            for _id, node in subgraph.nodes.items()
            if node.attributes.get("type") == "instruction"
        }
        return cls._create_path(instructions, subgraph.edges)

    @classmethod
    def _create_path(cls, nodes, edges):
        """
        Performs a randomized Kahn-variant topological sort algorithm.
        """
        path = []
        targets = {edge.target for edge in edges}
        choices = [node for node in nodes.values() if node.id not in targets]

        while choices:
            selection = random.choice(choices)
            choices.remove(selection)

            if selection in path:
                continue

            path.append(selection)
            successors = [
                nodes[edge.target] for edge in selection.target_edges() if edge.target in nodes
            ]

            for successor in successors:
                if successor in path:
                    continue

                all_sources_in_path = all(
                    nodes.get(edge.source) in path
                    for edge in successor.source_edges()
                    if edge.source in nodes
                )

                if not all_sources_in_path:
                    continue

                if successor not in choices:
                    choices.append(successor)

        if len(path) != len(nodes):
            missing = [node.id for node in nodes.values() if node not in path]
            raise RuntimeError(
                f"Topological sort incomplete. Processed {len(path)} of {len(nodes)} nodes. Missing: {missing}"
            )

        return path
