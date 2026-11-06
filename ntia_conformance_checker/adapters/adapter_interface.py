# SPDX-FileCopyrightText: 2026 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Blueprint interface for SBOM adapters."""

from abc import ABC, abstractmethod

from spdx_tools.spdx.validation.validation_message import ValidationMessage


def is_blank_string(value: object, noassertion: bool = False) -> bool:
    """
    Check whether a value is a blank string.

    Blank means whitespace-only, or ``NOASSERTION`` (any case) when
    ``noassertion`` is set. Use ``noassertion`` only for fields where the SPDX
    specification defines it (supplier, license, copyright). ``NONE`` is a
    statement, so it is not blank.

    Args:
        value: The value to check.
        noassertion: Whether ``NOASSERTION`` counts as blank.

    Returns:
        bool: True if ``value`` is a blank string.
    """
    if not isinstance(value, str):
        return False
    text = value.strip().upper()
    return not text or (noassertion and text == "NOASSERTION")


# One method per check keeps each adapter's answers independent.
class SbomAdapter(ABC):  # pylint: disable=too-many-public-methods
    """Abstract base class defining the standard interface for all SBOM adapters."""

    @abstractmethod
    def get_doc_spec_version(self) -> str | None:
        """Retrieve the document's specification version."""

    def check_doc_version(self) -> bool:
        """Check if the document's specification version exists."""
        return bool(self.get_doc_spec_version())

    @abstractmethod
    def check_author(self) -> bool:
        """Check if the author of SBOM data exists."""

    @abstractmethod
    def check_timestamp(self) -> bool:
        """Check if the SBOM creation timestamp exists."""

    @abstractmethod
    def get_sbom_name(self) -> str:
        """Retrieve the name of the SBOM."""

    @abstractmethod
    def get_components_without_names(
        self, reachable_ids: set[str]
    ) -> list[tuple[str, str]]:
        """
        Retrieve components missing a name.

        Returns:
            list[tuple[str, str]]: A list of tuples of the form
            (component_name, spdx_id). Consumers should extract the
            preferred value (name or SPDX ID) as needed.
        """

    @abstractmethod
    def get_components_without_versions(
        self, reachable_ids: set[str]
    ) -> list[tuple[str, str]]:
        """
        Retrieve components missing version information.

        Returns:
            list[tuple[str, str]]: A list of tuples of the form
            (component_name, spdx_id). Consumers should extract the
            preferred value (name or SPDX ID) as needed.
        """

    @abstractmethod
    def get_components_without_suppliers(
        self, reachable_ids: set[str]
    ) -> list[tuple[str, str]]:
        """
        Retrieve components missing supplier information.

        Returns:
            list[tuple[str, str]]: A list of tuples of the form
            (component_name, spdx_id). Consumers should extract the
            preferred value (name or SPDX ID) as needed.
        """

    @abstractmethod
    def get_components_without_identifiers(
        self, reachable_ids: set[str]
    ) -> list[tuple[str, str]]:
        """
        Retrieve components missing unique identifiers.

        SPDX 2: the SPDXID. SPDX 3: a package URL, a content identifier or an
        identifying external identifier on a reachable package (the spdxId
        does not count).

        Returns:
            list[tuple[str, str]]: A list of tuples of the form
            (component_name, spdx_id). Consumers should extract the
            preferred value (name or SPDX ID) as needed.
        """

    @abstractmethod
    def get_components_without_concluded_licenses(
        self, reachable_ids: set[str]
    ) -> list[tuple[str, str]]:
        """
        Retrieve components missing a concluded license.

        Returns:
            list[tuple[str, str]]: A list of tuples of the form
            (component_name, spdx_id). Consumers should extract the
            preferred value (name or SPDX ID) as needed.
        """

    @abstractmethod
    def get_components_without_copyright_texts(
        self, reachable_ids: set[str]
    ) -> list[tuple[str, str]]:
        """
        Retrieve components missing a copyright text.

        Returns:
            list[tuple[str, str]]: A list of tuples of the form
            (component_name, spdx_id). Consumers should extract the
            preferred value (name or SPDX ID) as needed.
        """

    @abstractmethod
    def check_dependency_relationships(self) -> bool:
        """Check if the SBOM document declares dependency information."""

    @abstractmethod
    def get_total_number_components(self) -> int:
        """
        Retrieve total number of components.

        Returns:
            int: The total number of components.
        """

    @abstractmethod
    def get_sbom_types(
        self, conformance_messages: list[ValidationMessage]
    ) -> list[str]:
        """Get SBOM types from the rootElement of the SpdxDocument.

        CISA Framing Software Component Transparency (2024) listed
        "SBOM type" as one of baseline attributes, see Table 1 (p. 22) in:
        https://www.cisa.gov/resources-tools/resources/framing-software-component-transparency-2024
        """

    # ---- Kind-scoped checks (SPDX 3 only; other adapters have no such kinds) ----

    def has_components_of_kind(  # pylint: disable=unused-argument
        self, kind: str, reachable_ids: set[str] | None
    ) -> bool:
        """Whether the SBOM has a component of ``kind`` (only a reachable one unless
        ``reachable_ids`` is ``None``)."""
        return False

    def system_stand_in(  # pylint: disable=unused-argument
        self, reachable_ids: set[str]
    ) -> tuple[str, str] | None:
        """``(name, spdx_id)`` of the model that stands for the system, if one
        does (see the SPDX 3 adapter); ``None`` otherwise."""
        return None

    def get_components_of_kind(  # pylint: disable=unused-argument
        self, kind: str, reachable_ids: set[str]
    ) -> list[tuple[str, str]]:
        """``(name, spdx_id)`` of every reachable component of ``kind``."""
        raise ValueError(f"{type(self).__name__} cannot check components of {kind!r}")

    def get_components_without_properties(  # pylint: disable=unused-argument
        self,
        kind: str,
        properties: tuple[str, ...],
        reachable_ids: set[str],
        via: tuple[str, ...] = (),
    ) -> list[tuple[str, str]]:
        """Components of ``kind`` that declare none of ``properties``, neither
        themselves nor on an element they link to through a ``via``
        relationship. A ``property/value`` entry needs that value."""
        raise ValueError(f"{type(self).__name__} cannot check components of {kind!r}")

    def get_components_without_hash(  # pylint: disable=unused-argument
        self,
        kind: str,
        algorithms: tuple[str, ...],
        reachable_ids: set[str],
        via: tuple[str, ...] = (),
    ) -> list[tuple[str, str]]:
        """Components of ``kind`` with no hash (of one of ``algorithms``, when
        given), neither themselves nor on an element linked through ``via``."""
        raise ValueError(f"{type(self).__name__} cannot check components of {kind!r}")

    # pylint: disable-next=unused-argument,too-many-arguments
    def get_components_without_relationships(
        self,
        kind: str,
        relationships: tuple[str, ...],
        direction: str,
        reachable_ids: set[str],
        *,
        completeness: bool = False,
        target_has: tuple[str, ...] = (),
    ) -> list[tuple[str, str]]:
        """Components of ``kind`` that are in none of ``relationships``; with
        ``completeness``, only a relationship declaring its completeness counts;
        with ``target_has``, only one to a target declaring one of them."""
        raise ValueError(f"{type(self).__name__} cannot check components of {kind!r}")

    def get_components_without_contact(  # pylint: disable=unused-argument
        self, kind: str, properties: tuple[str, ...], reachable_ids: set[str]
    ) -> list[tuple[str, str]]:
        """Components of ``kind`` whose agents in ``properties`` (such as
        ``originatedBy``) give no email address or URL."""
        raise ValueError(f"{type(self).__name__} cannot check components of {kind!r}")

    def document_declares_any(self, properties: tuple[str, ...]) -> bool:
        """Whether the document or its creation info declares any of ``properties``."""
        raise ValueError(f"{type(self).__name__} cannot check document properties")

    def document_has_contact(self, properties: tuple[str, ...]) -> bool:
        """Whether an agent in the creation info's ``properties`` (such as
        ``createdBy``) gives an email address or URL."""
        raise ValueError(f"{type(self).__name__} cannot check document properties")
