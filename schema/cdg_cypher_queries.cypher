// ============================================================
// CryptoDep-LLM — Neo4j Cypher Queries for CDG v1.0
// Poltek SSN | Quantum-Ready Cryptography Pillar
// ============================================================

// ── 1. SCHEMA CONSTRAINTS & INDEXES ──────────────────────────

CREATE CONSTRAINT cdg_node_id IF NOT EXISTS
  FOR (n:CDGNode) REQUIRE n.node_id IS UNIQUE;

CREATE INDEX idx_algo_family IF NOT EXISTS
  FOR (n:CryptoAlgorithm) ON (n.algorithm_family);

CREATE INDEX idx_vuln_class IF NOT EXISTS
  FOR (n:CryptoAlgorithm) ON (n.quantum_vuln_class);

CREATE INDEX idx_migration_priority IF NOT EXISTS
  FOR (n:CryptoAlgorithm) ON (n.migration_priority);

CREATE INDEX idx_pqc_algo_id IF NOT EXISTS
  FOR (n:PQCAlgorithm) ON (n.algorithm_id);

CREATE INDEX idx_component_boundary IF NOT EXISTS
  FOR (n:AppComponent) ON (n.is_boundary);

CREATE INDEX idx_business_criticality IF NOT EXISTS
  FOR (n:BusinessProcess) ON (n.criticality);


// ── 2. NODE CREATION TEMPLATES ─────────────────────────────

// Create CryptoAlgorithm node
MERGE (a:CDGNode:CryptoAlgorithm {node_id: $node_id})
SET a += {
  label:                   $label,
  algorithm_family:        $algorithm_family,
  parameter_set:           $parameter_set,
  key_size_bits:           $key_size_bits,
  use_context:             $use_context,
  quantum_vuln_class:      $quantum_vuln_class,
  migration_priority:      $migration_priority,
  migration_urgency_score: $migration_urgency_score,
  hndl_risk:               $hndl_risk,
  source_ref:              $source_ref,
  confidence:              $confidence,
  detected_by:             $detected_by,
  cbom_ref:                $cbom_ref
};

// Create PQCAlgorithm node
MERGE (p:CDGNode:PQCAlgorithm {node_id: $node_id})
SET p += {
  label:            $label,
  algorithm_id:     $algorithm_id,
  fips_standard:    $fips_standard,
  security_level:   $security_level,
  primitive_type:   $primitive_type,
  math_basis:       $math_basis,
  replaces:         $replaces,
  hybrid_mode_supported: $hybrid_mode_supported,
  liboqs_available: $liboqs_available
};

// Create CryptoLibrary node
MERGE (l:CDGNode:CryptoLibrary {node_id: $node_id})
SET l += {
  label:         $label,
  library_name:  $library_name,
  version:       $version,
  language:      $language,
  import_path:   $import_path,
  pqc_ready:     $pqc_ready,
  cve_count:     $cve_count,
  source_ref:    $source_ref
};

// Create AppComponent node
MERGE (c:CDGNode:AppComponent {node_id: $node_id})
SET c += {
  label:          $label,
  component_type: $component_type,
  language:       $language,
  file_path:      $file_path,
  owns_crypto:    $owns_crypto,
  is_boundary:    $is_boundary,
  source_ref:     $source_ref
};

// Create BusinessProcess node
MERGE (b:CDGNode:BusinessProcess {node_id: $node_id})
SET b += {
  label:               $label,
  criticality:         $criticality,
  owner:               $owner,
  bssn_system_id:      $bssn_system_id,
  regulatory_scope:    $regulatory_scope
};


// ── 3. EDGE CREATION TEMPLATES ─────────────────────────────

// implements: CryptoLibrary → CryptoAlgorithm
MATCH (lib:CryptoLibrary {node_id: $source_id})
MATCH (algo:CryptoAlgorithm {node_id: $target_id})
MERGE (lib)-[r:IMPLEMENTS {edge_id: $edge_id}]->(algo)
SET r += {confidence: $confidence, evidence: $evidence, cbom_dep_type: "implements"};

// uses: AppComponent → CryptoLibrary
MATCH (comp:AppComponent {node_id: $source_id})
MATCH (lib:CryptoLibrary {node_id: $target_id})
MERGE (comp)-[r:USES {edge_id: $edge_id}]->(lib)
SET r += {confidence: $confidence, evidence: $evidence, cbom_dep_type: "uses"};

// migrates_to: CryptoAlgorithm → PQCAlgorithm (CORE CDG EDGE)
MATCH (algo:CryptoAlgorithm {node_id: $source_id})
MATCH (pqc:PQCAlgorithm {node_id: $target_id})
MERGE (algo)-[r:MIGRATES_TO {edge_id: $edge_id}]->(pqc)
SET r += {confidence: $confidence, evidence: $evidence};

// depends_on: AppComponent → AppComponent
MATCH (a:AppComponent {node_id: $source_id})
MATCH (b:AppComponent {node_id: $target_id})
MERGE (a)-[r:DEPENDS_ON {edge_id: $edge_id}]->(b)
SET r += {confidence: $confidence, evidence: $evidence};

// exposes_via: BusinessProcess → Protocol
MATCH (bp:BusinessProcess {node_id: $source_id})
MATCH (proto:Protocol {node_id: $target_id})
MERGE (bp)-[r:EXPOSES_VIA {edge_id: $edge_id}]->(proto)
SET r += {confidence: $confidence, evidence: $evidence};

// relies_on: Protocol → CryptoAlgorithm
MATCH (proto:Protocol {node_id: $source_id})
MATCH (algo:CryptoAlgorithm {node_id: $target_id})
MERGE (proto)-[r:RELIES_ON {edge_id: $edge_id}]->(proto)
SET r += {confidence: $confidence, evidence: $evidence};


// ── 4. MIGRATION PRIORITY QUERIES ──────────────────────────

// Q1: All quantum-vulnerable algorithms ordered by urgency score
MATCH (a:CryptoAlgorithm {quantum_vuln_class: "quantum_vulnerable"})
RETURN a.label, a.algorithm_family, a.migration_urgency_score,
       a.migration_priority, a.hndl_risk, a.source_ref
ORDER BY a.migration_urgency_score DESC;

// Q2: Full migration path for a specific algorithm
MATCH path = (bp:BusinessProcess)-[:EXPOSES_VIA|DEPENDS_ON*0..3]->(comp:AppComponent)
             -[:USES]->(lib:CryptoLibrary)
             -[:IMPLEMENTS]->(algo:CryptoAlgorithm {quantum_vuln_class: "quantum_vulnerable"})
             -[:MIGRATES_TO]->(pqc:PQCAlgorithm)
RETURN bp.label AS business_system,
       comp.label AS component,
       lib.label AS library,
       algo.label AS current_algo,
       pqc.algorithm_id AS recommended_pqc,
       algo.migration_urgency_score AS urgency
ORDER BY urgency DESC
LIMIT 50;

// Q3: Graph centrality candidates (components touching most vulnerable algos)
MATCH (comp:AppComponent)-[:USES]->(lib:CryptoLibrary)
      -[:IMPLEMENTS]->(algo:CryptoAlgorithm {quantum_vuln_class: "quantum_vulnerable"})
RETURN comp.label, comp.file_path, count(DISTINCT algo) AS vuln_algo_count,
       comp.is_boundary AS is_trust_boundary
ORDER BY vuln_algo_count DESC, is_trust_boundary DESC
LIMIT 20;

// Q4: HNDL risk — algorithms protecting long-lived data
MATCH (a:CryptoAlgorithm {hndl_risk: true})
OPTIONAL MATCH (l:CryptoLibrary)-[:IMPLEMENTS]->(a)
OPTIONAL MATCH (c:AppComponent)-[:USES]->(l)
RETURN a.label, a.parameter_set, collect(DISTINCT c.label) AS affected_components
ORDER BY a.migration_urgency_score DESC;

// Q5: Libraries NOT yet PQC-ready that implement vulnerable algorithms
MATCH (lib:CryptoLibrary {pqc_ready: false})
      -[:IMPLEMENTS]->(algo:CryptoAlgorithm {quantum_vuln_class: "quantum_vulnerable"})
RETURN lib.library_name, lib.version, lib.language,
       collect(algo.parameter_set) AS vulnerable_algos,
       count(algo) AS count
ORDER BY count DESC;

// Q6: Quantum readiness score (aggregate)
MATCH (a:CryptoAlgorithm)
WITH count(a) AS total,
     sum(CASE WHEN a.quantum_vuln_class = "quantum_vulnerable" THEN 1 ELSE 0 END) AS vuln_count,
     sum(CASE WHEN a.quantum_vuln_class = "quantum_safe_pqc" THEN 1 ELSE 0 END) AS safe_count
RETURN total, vuln_count, safe_count,
       round(100.0 * safe_count / total, 1) AS quantum_readiness_pct;

// Q7: Multi-hop dependency chain (LLM multi-hop eval — DependEval baseline)
MATCH path = (bp:BusinessProcess {criticality: "critical"})
             -[:EXPOSES_VIA|DEPENDS_ON*1..4]->(comp:AppComponent)
             -[:USES]->(lib:CryptoLibrary)
             -[:IMPLEMENTS]->(algo:CryptoAlgorithm)
             -[:MIGRATES_TO]->(pqc:PQCAlgorithm)
WHERE algo.quantum_vuln_class = "quantum_vulnerable"
RETURN length(path) AS chain_depth,
       bp.label AS system,
       [n IN nodes(path) | n.label] AS dependency_chain,
       algo.migration_urgency_score AS urgency
ORDER BY chain_depth DESC, urgency DESC;

// Q8: BSSN/SPBE systems with critical crypto debt
MATCH (bp:BusinessProcess)
WHERE bp.bssn_system_id IS NOT NULL
      AND ANY(scope IN bp.regulatory_scope WHERE scope IN ["SPBE", "PP_82_2023"])
MATCH (bp)-[:EXPOSES_VIA*0..3]->(comp:AppComponent)
          -[:USES]->(lib:CryptoLibrary)
          -[:IMPLEMENTS]->(algo:CryptoAlgorithm {quantum_vuln_class: "quantum_vulnerable"})
RETURN bp.bssn_system_id, bp.label, bp.criticality,
       count(DISTINCT algo) AS vuln_algo_count
ORDER BY vuln_algo_count DESC;
