"""Benchmark repository definitions (PRD Section 10.1).

Repos used for evaluation:
  - OWASP WebGoat (Java, 48k LOC) — primary benchmark, full ground truth
  - Spring Petclinic (Java, 12k LOC) — full ground truth
  - Apache Kafka (Java, 180k LOC) — partial (30 files)
  - Django REST Framework (Python, 35k LOC) — full ground truth
  - cryptography.io examples (Python, 8k LOC) — full annotation

Ground truth files: tests/eval/ground_truth/{repo}_gt.json
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class BenchmarkRepo:
    name: str
    url: str
    language: str
    loc_approx: int
    ground_truth_file: str
    partial_annotation: bool = False
    annotation_files: Optional[int] = None


BENCHMARK_REPOS: list[BenchmarkRepo] = [
    BenchmarkRepo(
        name="webgoat",
        url="https://github.com/WebGoat/WebGoat",
        language="java",
        loc_approx=48_000,
        ground_truth_file="tests/eval/ground_truth/webgoat_gt.json",
    ),
    BenchmarkRepo(
        name="spring-petclinic",
        url="https://github.com/spring-projects/spring-petclinic",
        language="java",
        loc_approx=12_000,
        ground_truth_file="tests/eval/ground_truth/spring_petclinic_gt.json",
    ),
    BenchmarkRepo(
        name="kafka",
        url="https://github.com/apache/kafka",
        language="java",
        loc_approx=180_000,
        ground_truth_file="tests/eval/ground_truth/kafka_gt.json",
        partial_annotation=True,
        annotation_files=30,
    ),
    BenchmarkRepo(
        name="djangorestframework",
        url="https://github.com/encode/django-rest-framework",
        language="python",
        loc_approx=35_000,
        ground_truth_file="tests/eval/ground_truth/drf_gt.json",
    ),
    BenchmarkRepo(
        name="cryptography-examples",
        url="https://github.com/pyca/cryptography",
        language="python",
        loc_approx=8_000,
        ground_truth_file="tests/eval/ground_truth/cryptography_gt.json",
    ),
]
