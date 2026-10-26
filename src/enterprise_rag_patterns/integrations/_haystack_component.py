"""Optional native component, imported by construction or pipeline deserialization."""

from collections.abc import Callable
from typing import Any, cast

from haystack import Document, component

from .haystack import FERPAHaystackFilter


@component
class RegisteredFERPAHaystackFilter(FERPAHaystackFilter):
    """Stable serialization target for the lazily constructed public filter."""

    @cast(Callable[[Callable[..., Any]], Callable[..., Any]], component.output_types(filtered_documents=list[Document]))
    def run(
        self,
        documents: list[Document],
        student_id: str,
        institution_id: str,
        permitted_categories: set[str] | None = None,
    ) -> dict[str, list[Any]]:
        return FERPAHaystackFilter.run(
            self,
            documents=documents,
            student_id=student_id,
            institution_id=institution_id,
            permitted_categories=permitted_categories,
        )
