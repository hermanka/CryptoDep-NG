#!/usr/bin/env python
"""Clear all data from Neo4j database."""

import os
import subprocess
import sys
from neo4j import GraphDatabase
from dotenv import load_dotenv

def check_docker_status():
    """Check if Neo4j Docker container is running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=neo4j", "--format", "{{.Names}}\t{{.Status}}"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout:
            print("✓ Neo4j container status:")
            print(f"  {result.stdout.strip()}")
            return True
        else:
            print("✗ Neo4j container not found or not running")
            return False
    except Exception as e:
        print(f"✗ Error checking Docker: {e}")
        return False

def clear_neo4j_database():
    """Connect to Neo4j and clear all nodes/edges."""
    load_dotenv()
    
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "neo4j1234")
    
    print(f"\nConnecting to Neo4j:")
    print(f"  URI: {uri}")
    print(f"  User: {user}")
    
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        
        # Verify connection
        with driver.session() as session:
            driver.verify_connectivity()
            print("✓ Connected to Neo4j")
        
        # Delete all nodes and edges
        print("\nExecuting: MATCH (n) DETACH DELETE n")
        with driver.session() as session:
            result = session.run("MATCH (n) DETACH DELETE n")
            summary = result.consume()
            print(f"✓ Deletion executed")
            print(f"  Nodes deleted: {summary.counters.nodes_deleted}")
            print(f"  Relationships deleted: {summary.counters.relationships_deleted}")
        
        # Verify all data is deleted
        print("\nVerifying deletion...")
        with driver.session() as session:
            result = session.run("MATCH (n) RETURN count(n) as count")
            count = result.single()["count"]
            print(f"✓ Verification query: MATCH (n) RETURN count(n)")
            print(f"  Result: {count}")
            
            if count == 0:
                print("\n✓ SUCCESS: Neo4j database is now empty")
                driver.close()
                return True
            else:
                print(f"\n✗ FAILED: Database still has {count} nodes")
                driver.close()
                return False
                
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("Neo4j Database Clear Task")
    print("=" * 60)
    
    # Step 1: Check Docker status
    if not check_docker_status():
        print("\nAttempting to start Neo4j container...")
        try:
            subprocess.run(["docker", "start", "neo4j"], check=True, timeout=30)
            print("✓ Neo4j container started")
        except Exception as e:
            print(f"✗ Failed to start container: {e}")
            sys.exit(1)
    
    # Step 2 & 3: Clear and verify
    if clear_neo4j_database():
        print("\n" + "=" * 60)
        print("Task completed successfully!")
        print("=" * 60)
        sys.exit(0)
    else:
        print("\n" + "=" * 60)
        print("Task failed!")
        print("=" * 60)
        sys.exit(1)
