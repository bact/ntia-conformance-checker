# SPDX-FileCopyrightText: 2026 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Graph utilities for SPDX 2 and SPDX 3."""

import logging
from collections import deque
from typing import TYPE_CHECKING, Any, cast

from spdx_python_model.bindings import v3_0_1 as spdx3
from spdx_tools.spdx.model.relationship import RelationshipType

from .constants import (
    SPDX2_RELATIONSHIP_TRAVERSAL,
    SPDX3_RELATIONSHIP_TRAVERSAL,
    TraversalDirection,
)
from .spdx3_utils import SPDX3_INDIVIDUAL_ELEMENT_IRIS

if TYPE_CHECKING:
    from spdx_tools.spdx.model.document import Document


def _get_spdx2_doc_id(spdx2_doc: "Document") -> str:
    """Return the SPDX ID of an SPDX 2 document, ``SPDXRef-DOCUMENT`` by default."""
    creation_info = getattr(spdx2_doc, "creation_info", None)
    doc_id = getattr(creation_info, "spdx_id", None)
    return doc_id if isinstance(doc_id, str) and doc_id else "SPDXRef-DOCUMENT"


def _collect_spdx2_external_document_ref_ids(spdx2_doc: "Document") -> set[str]:
    """
    Retrieve the IDs of external documents declared in an SPDX 2 document.

    These are the ``DocumentRef-<idstring>`` values of ``ExternalDocumentRef``
    (SPDX 2.3 clause 6.6, External document references field).

    Returns:
        set[str]: Declared external document reference IDs.
    """
    creation_info = getattr(spdx2_doc, "creation_info", None)
    ext_refs = getattr(creation_info, "external_document_refs", None) or []
    return {
        ref.document_ref_id
        for ref in ext_refs
        if isinstance(getattr(ref, "document_ref_id", None), str)
    }


def _is_spdx2_external_element_id(
    element_id: str, external_doc_ref_ids: set[str]
) -> bool:
    """
    Check whether an SPDX 2 element ID refers to an element in a declared external document.

    SPDX 2.3 clause 11.1 (Table 69) writes either end of a relationship as
    ``["DocumentRef-"[idstring]":"]SPDXID``, where the optional prefix is
    "a reference to an external SPDX Document as described in 6.6".
    Clause 6.6 declares that prefix in an ``ExternalDocumentRef``.
    The element is defined in the external document, not in this one, so it
    exists when its prefix is declared. The external document itself is
    ``DocumentRef-<idstring>:SPDXRef-DOCUMENT``.

    Args:
        element_id: Element ID used in a relationship.
        external_doc_ref_ids: Declared external document reference IDs.

    Returns:
        bool: True if the ID is ``<declared DocumentRef>:<SPDXID>``.
    """
    doc_ref_id, separator, local_id = element_id.partition(":")
    return bool(separator and local_id) and doc_ref_id in external_doc_ref_ids


def _collect_spdx2_known_and_package_ids(
    spdx2_doc: "Document",
) -> tuple[set[str], set[str]]:
    """
    Retrieve known entity IDs (packages, files, snippets, document) and package IDs for SPDX 2.

    Returns:
        tuple: (all_known_ids, all_package_ids)
    """
    doc_id = _get_spdx2_doc_id(spdx2_doc)

    package_ids = {
        pkg.spdx_id
        for pkg in getattr(spdx2_doc, "packages", [])
        if isinstance(pkg.spdx_id, str)
    }
    file_ids = {
        f.spdx_id for f in getattr(spdx2_doc, "files", []) if isinstance(f.spdx_id, str)
    }
    snippet_ids = {
        s.spdx_id
        for s in getattr(spdx2_doc, "snippets", [])
        if isinstance(s.spdx_id, str)
    }
    all_known_ids = package_ids | file_ids | snippet_ids | {doc_id}
    return all_known_ids, package_ids


def _collect_spdx3_known_and_package_ids(
    object_set: spdx3.SHACLObjectSet,
) -> tuple[set[str], set[str]]:
    """
    Retrieve all known object IDs and package IDs for SPDX 3.

    Returns:
        tuple: (all_known_ids, all_package_ids)
    """
    all_known_ids = {
        getattr(obj, "spdxId")
        for obj in object_set.objects
        if isinstance(getattr(obj, "spdxId", None), str)
    } | SPDX3_INDIVIDUAL_ELEMENT_IRIS  # NoneElement and the like need no definition
    package_ids = {
        getattr(obj, "spdxId")
        for obj in object_set.objects
        if isinstance(obj, spdx3.software_Package)
        and isinstance(getattr(obj, "spdxId", None), str)
    }
    return all_known_ids, package_ids


def _check_spdx2_ids(
    spdx2_doc: "Document", reachable_node_ids: set[str]
) -> tuple[set[str], set[str], dict[str, list[str]]]:
    """
    Collect known and package IDs of an SPDX 2 document and find missing elements.

    Args:
        spdx2_doc: Parsed SPDX 2 document.
        reachable_node_ids: Node IDs reachable from the roots.

    Returns:
        tuple: (all_known_ids, all_package_ids, unknown_pointer_edges), where
            all_known_ids includes reachable elements in declared external
            documents.
    """
    all_known_ids, all_package_ids = _collect_spdx2_known_and_package_ids(spdx2_doc)
    external_doc_ref_ids = _collect_spdx2_external_document_ref_ids(spdx2_doc)
    # Elements in declared external documents exist, but not in this one
    all_known_ids |= {
        node_id
        for node_id in reachable_node_ids
        if _is_spdx2_external_element_id(node_id, external_doc_ref_ids)
    }
    unknown_pointer_edges = _find_spdx2_unknown_pointer_edges(
        spdx2_doc, all_known_ids, external_doc_ref_ids
    )
    return all_known_ids, all_package_ids, unknown_pointer_edges


def _find_missing_targets(
    edges: dict[str, list[str]], all_known_ids: set[str]
) -> dict[str, list[str]]:
    """
    Find the targets of edges that are not known elements.

    Args:
        edges: Source ID to target IDs.
        all_known_ids: IDs of known elements.

    Returns:
        dict[str, list[str]]: Source ID to its missing target IDs, for sources
            that have any.
    """
    missing_edges: dict[str, list[str]] = {}
    for source_id, target_ids in edges.items():
        missing_targets = [t for t in target_ids if t not in all_known_ids]
        if missing_targets:
            missing_edges[source_id] = missing_targets
    return missing_edges


def analyze_graph_connectivity(
    sbom_spec: str, parsed_data: Any, spdx3_doc: Any = None
) -> tuple[set[str], set[str], dict[str, list[str]], bool]:
    """
    Analyze graph connectivity to find reachable components and unknown pointers.

    Connectivity is evaluated at the component (package) level because
    components represent the primary unit of software conformance in
    minimum elements standards.

    Returns:
        tuple: (reachable_component_ids, floating_component_ids,
            unknown_pointer_edges, has_unknown_pointers)
    """
    if not parsed_data or (sbom_spec == "spdx3" and not spdx3_doc):
        return set(), set(), {}, False

    queue, connection_map, declared_edges = _build_graph(
        sbom_spec, parsed_data, spdx3_doc
    )
    reachable_node_ids = _traverse(queue, connection_map)
    all_known_ids: set[str] = set()
    all_package_ids: set[str] = set()
    unknown_pointer_edges: dict[str, list[str]] = {}

    if sbom_spec == "spdx2":
        all_known_ids, all_package_ids, unknown_pointer_edges = _check_spdx2_ids(
            cast("Document", parsed_data), reachable_node_ids
        )
    elif sbom_spec == "spdx3":
        all_known_ids, all_package_ids = _collect_spdx3_known_and_package_ids(
            cast("spdx3.SHACLObjectSet", parsed_data)
        )
        unknown_pointer_edges = _find_missing_targets(declared_edges, all_known_ids)

    reachable_component_ids = reachable_node_ids & all_package_ids
    floating_component_ids = all_package_ids - reachable_component_ids
    has_unknown_pointers = bool(unknown_pointer_edges)

    if not reachable_node_ids.issubset(all_known_ids) and not has_unknown_pointers:
        logging.error(
            "Traversal bug: BFS reached a node absent from all_known_ids, "
            "but unknown_pointer_edges did not record it."
        )

    return (
        reachable_component_ids,
        floating_component_ids,
        unknown_pointer_edges,
        has_unknown_pointers,
    )


def _find_spdx2_unknown_pointer_edges(
    spdx2_doc: "Document", all_known_ids: set[str], external_doc_ref_ids: set[str]
) -> dict[str, list[str]]:
    """
    Find SPDX 2 composition relationships that point to a missing element.

    SPDX 2.3 clause 11.1 (Table 69) allows an SPDX ID at both ends of a
    relationship, so either end can be missing. ``NONE`` and ``NOASSERTION``
    state that there are no relationships or that it is not known; they are
    not elements and are never missing.

    Each relationship is reported as written in the document, from its
    ``spdxElementId`` to its ``relatedSpdxElement``, so a reverse relationship
    such as ``A DEPENDENCY_OF B`` with B missing is reported as A to B.
    A relationship whose ``spdxElementId`` is missing while its
    ``relatedSpdxElement`` is known is reported from the known element.

    Args:
        spdx2_doc: Parsed SPDX 2 document.
        all_known_ids: IDs of the elements defined in the document.
        external_doc_ref_ids: Declared external document reference IDs.

    Returns:
        dict[str, list[str]]: Known element ID to the missing element IDs it
            links to.
    """

    def is_known(element_id: str) -> bool:
        return element_id in all_known_ids or _is_spdx2_external_element_id(
            element_id, external_doc_ref_ids
        )

    unknown_pointer_edges: dict[str, list[str]] = {}
    for rel in getattr(spdx2_doc, "relationships", None) or []:
        source_id = rel.spdx_element_id
        target_id = rel.related_spdx_element_id
        # NONE and NOASSERTION are not str and point to no element
        if not isinstance(source_id, str) or not isinstance(target_id, str):
            continue
        if rel.relationship_type.name not in SPDX2_RELATIONSHIP_TRAVERSAL:
            continue

        if not is_known(target_id):
            missing_targets = unknown_pointer_edges.setdefault(source_id, [])
            if target_id not in missing_targets:
                missing_targets.append(target_id)
        elif not is_known(source_id):
            missing_sources = unknown_pointer_edges.setdefault(target_id, [])
            if source_id not in missing_sources:
                missing_sources.append(source_id)
    return unknown_pointer_edges


def _build_spdx2_graph(spdx2_doc: "Document") -> tuple[list[str], dict[str, list[str]]]:
    """
    Build the initial queue and connection map for SPDX 2.

    Roots are the elements that the document describes: ``SPDXRef-DOCUMENT
    DESCRIBES A`` or ``A DESCRIBED_BY SPDXRef-DOCUMENT`` (SPDX 2.3 clause 11.1,
    Table 68; the document ID is from clause 6.3).

    Edges point from parent to child. A forward relationship such as
    ``A CONTAINS B`` adds an edge from A to B. A reverse relationship such as
    ``B CONTAINED_BY A`` or ``B BUILD_DEPENDENCY_OF A`` also adds an edge
    from A to B. ``SPDX2_RELATIONSHIP_TRAVERSAL`` holds the direction of each
    type.
    """
    queue: list[str] = []
    graph_connection_map: dict[str, list[str]] = {}

    if not spdx2_doc.relationships:
        return queue, graph_connection_map

    doc_id = _get_spdx2_doc_id(spdx2_doc)

    for rel in spdx2_doc.relationships:
        source_id = rel.spdx_element_id
        target_id = rel.related_spdx_element_id

        if not isinstance(source_id, str) or not isinstance(target_id, str):
            continue

        # Get the root elements
        if rel.relationship_type == RelationshipType.DESCRIBES and source_id in (
            doc_id,
            "SPDXRef-DOCUMENT",
        ):
            queue.append(target_id)
        # DESCRIBED_BY is a reverse of DESCRIBES
        elif rel.relationship_type == RelationshipType.DESCRIBED_BY and target_id in (
            doc_id,
            "SPDXRef-DOCUMENT",
        ):
            queue.append(source_id)

        # Build the graph connection map
        direction = SPDX2_RELATIONSHIP_TRAVERSAL.get(rel.relationship_type.name)
        if direction is TraversalDirection.FORWARD:
            graph_connection_map.setdefault(source_id, []).append(target_id)
        elif direction is TraversalDirection.REVERSE:
            graph_connection_map.setdefault(target_id, []).append(source_id)
    return queue, graph_connection_map


def _extract_spdx3_relationship_edges(
    obj: spdx3.Relationship,
    graph_connection_map: dict[str, list[str]],
    declared_edges: dict[str, list[str]],
) -> None:
    """
    Helper to extract explicit relationship edges.

    ``graph_connection_map`` gets edges in traversal direction, from parent to
    child (see ``SPDX3_RELATIONSHIP_TRAVERSAL``). ``declared_edges`` gets the
    edges to check for missing elements: ``from`` to each ``to`` as written,
    and, for a reverse type, also each ``to`` to ``from``, because traversal
    reaches ``from`` through it.
    """
    rel_type_iri = getattr(obj, "relationshipType", "")
    if not rel_type_iri:
        return

    # Extract the actual name from the IRI (e.g., ".../contains" -> "contains")
    rel_name = rel_type_iri.split("/")[-1]

    direction = SPDX3_RELATIONSHIP_TRAVERSAL.get(rel_name)
    if direction is None:
        return

    from_ = getattr(obj, "from_", None)
    from_id = from_ if isinstance(from_, str) else getattr(from_, "spdxId", None)

    if not from_id:
        return

    to_ids = [
        t if isinstance(t, str) else getattr(t, "spdxId", "")
        for t in getattr(obj, "to", [])
    ]
    to_ids = [t for t in to_ids if t]

    declared_edges.setdefault(from_id, []).extend(to_ids)
    if direction is TraversalDirection.FORWARD:
        graph_connection_map.setdefault(from_id, []).extend(to_ids)
    else:
        for to_id in to_ids:
            graph_connection_map.setdefault(to_id, []).append(from_id)
            declared_edges.setdefault(to_id, []).append(from_id)


def _extract_spdx3_collection_edges(
    obj: spdx3.ElementCollection, graph_connection_map: dict[str, list[str]]
) -> None:
    """Helper to extract implicit collection edges (e.g. Sbom, Document)."""
    col_id = getattr(obj, "spdxId", None)
    if not col_id:
        return

    if col_id not in graph_connection_map:
        graph_connection_map[col_id] = []

    for elem in getattr(obj, "rootElement", []):
        e_id = elem if isinstance(elem, str) else getattr(elem, "spdxId", "")
        if e_id:
            graph_connection_map[col_id].append(e_id)


def _build_spdx3_graph(
    object_set: spdx3.SHACLObjectSet, spdx3_doc: spdx3.SpdxDocument | None
) -> tuple[list[str], dict[str, list[str]], dict[str, list[str]]]:
    """
    Build the initial queue and connection maps for SPDX 3.

    Returns:
        tuple: (queue, graph_connection_map, declared_edges), where
            graph_connection_map is in traversal direction and declared_edges
            holds the edges to check for missing elements.
    """
    queue: list[str] = []
    graph_connection_map: dict[str, list[str]] = {}
    declared_edges: dict[str, list[str]] = {}

    doc_id = getattr(spdx3_doc, "spdxId", None) if spdx3_doc else None

    if spdx3_doc and getattr(spdx3_doc, "rootElement", None):
        for root in spdx3_doc.rootElement:
            root_id = root if isinstance(root, str) else getattr(root, "spdxId", "")
            if root_id:
                queue.append(root_id)

    # Build the graph connection map
    for obj in object_set.objects:
        # Capture explicit relationships from Relationship objects
        if isinstance(obj, spdx3.Relationship):
            from_ = getattr(obj, "from_", None)
            from_id = (
                from_ if isinstance(from_, str) else getattr(from_, "spdxId", None)
            )

            # If a relationship originates from the Document itself,
            # its targets are treated as Roots.
            if doc_id and from_id == doc_id:
                to_ids = [
                    t if isinstance(t, str) else getattr(t, "spdxId", "")
                    for t in getattr(obj, "to", [])
                ]
                queue.extend([t for t in to_ids if t])

            # Normal relationships between packages build the map
            else:
                _extract_spdx3_relationship_edges(
                    obj, graph_connection_map, declared_edges
                )

        # Capture implicit relationships from Collections (like Sbom, Bom, etc.)
        if isinstance(obj, spdx3.ElementCollection):
            _extract_spdx3_collection_edges(obj, graph_connection_map)
            _extract_spdx3_collection_edges(obj, declared_edges)

    return queue, graph_connection_map, declared_edges


def _build_graph(
    sbom_spec: str, parsed_data: Any, spdx3_doc: Any = None
) -> tuple[list[str], dict[str, list[str]], dict[str, list[str]]]:
    """
    Build the roots, the traversal map and the edges to check for missing elements.

    Returns:
        tuple: (queue, graph_connection_map, declared_edges)
    """
    if sbom_spec == "spdx2":
        queue, graph_connection_map = _build_spdx2_graph(parsed_data)
        # SPDX 2 checks relationships as written; see
        # _find_spdx2_unknown_pointer_edges
        return queue, graph_connection_map, {}
    if sbom_spec == "spdx3":
        return _build_spdx3_graph(parsed_data, spdx3_doc)
    return [], {}, {}


def _traverse(queue: list[str], graph_connection_map: dict[str, list[str]]) -> set[str]:
    """
    Find all nodes reachable from the roots by using Breadth-First Search.

    Args:
        queue: Root node IDs.
        graph_connection_map: Edges from parent to children.

    Returns:
        set[str]: Reachable node IDs, roots included.
    """
    reachable_node_ids: set[str] = set(queue)
    pending = deque(queue)
    while pending:
        current_id = pending.popleft()
        for target_id in graph_connection_map.get(current_id, []):
            if target_id not in reachable_node_ids:
                reachable_node_ids.add(target_id)
                pending.append(target_id)
    return reachable_node_ids


def get_reachable_nodes(
    sbom_spec: str, parsed_data: Any, spdx3_doc: Any = None
) -> tuple[set[str], dict[str, list[str]]]:
    """
    Get all nodes connected to the root by using Breadth-First Search.

    Returns:
        tuple: (reachable_node_ids, graph_connection_map), where
            graph_connection_map holds edges from parent to children.
    """
    if not parsed_data or (sbom_spec == "spdx3" and not spdx3_doc):
        return set(), {}

    queue, graph_connection_map, _ = _build_graph(sbom_spec, parsed_data, spdx3_doc)
    return _traverse(queue, graph_connection_map), graph_connection_map
