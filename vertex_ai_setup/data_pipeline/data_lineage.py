#!/usr/bin/env python3
"""
Data Versioning and Lineage Tracking for VulnHunter
Implements comprehensive data versioning, lineage tracking, and provenance management.
"""

import json
import logging
import os
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from pathlib import Path
from enum import Enum

import pandas as pd
import numpy as np
from google.cloud import aiplatform
from google.cloud import storage
from google.cloud import datacatalog_v1
from google.api_core import exceptions
import networkx as nx
from sqlalchemy import create_engine, Column, String, DateTime, Integer, JSON, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class LineageEventType(Enum):
    """Types of lineage events"""
    DATASET_CREATED = "dataset_created"
    DATASET_UPDATED = "dataset_updated"
    DATASET_MERGED = "dataset_merged"
    DATASET_FILTERED = "dataset_filtered"
    FEATURE_EXTRACTED = "feature_extracted"
    DATA_VALIDATED = "data_validated"
    MODEL_TRAINED = "model_trained"
    MODEL_DEPLOYED = "model_deployed"

@dataclass
class DataVersion:
    """Represents a version of a dataset"""
    version_id: str
    dataset_name: str
    version_number: str
    creation_time: datetime
    checksum: str
    size_bytes: int
    record_count: int
    schema_version: str
    parent_versions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

@dataclass
class LineageEvent:
    """Represents a data lineage event"""
    event_id: str
    event_type: LineageEventType
    timestamp: datetime
    source_datasets: List[str]
    target_datasets: List[str]
    transformation: str
    parameters: Dict[str, Any]
    user: str
    execution_context: Dict[str, Any]

# Database models for persistent storage
class DataVersionModel(Base):
    __tablename__ = 'data_versions'

    version_id = Column(String, primary_key=True)
    dataset_name = Column(String, nullable=False)
    version_number = Column(String, nullable=False)
    creation_time = Column(DateTime, nullable=False)
    checksum = Column(String, nullable=False)
    size_bytes = Column(Integer)
    record_count = Column(Integer)
    schema_version = Column(String)
    parent_versions = Column(JSON)
    metadata = Column(JSON)
    tags = Column(JSON)

class LineageEventModel(Base):
    __tablename__ = 'lineage_events'

    event_id = Column(String, primary_key=True)
    event_type = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    source_datasets = Column(JSON)
    target_datasets = Column(JSON)
    transformation = Column(String)
    parameters = Column(JSON)
    user = Column(String)
    execution_context = Column(JSON)

class VulnHunterDataLineageTracker:
    """
    Comprehensive data lineage and versioning system for VulnHunter
    with provenance tracking, version control, and impact analysis.
    """

    def __init__(self,
                 project_id: str,
                 location: str = "us-central1",
                 database_url: str = None):
        self.project_id = project_id
        self.location = location
        self.storage_client = storage.Client(project=project_id)

        # Initialize Vertex AI
        aiplatform.init(project=project_id, location=location)

        # Storage configuration
        self.lineage_bucket = f"{project_id}-vulnhunter-lineage"
        self.versions_bucket = f"{project_id}-vulnhunter-versions"

        # Database configuration
        if database_url:
            self.engine = create_engine(database_url)
            Base.metadata.create_all(self.engine)
            Session = sessionmaker(bind=self.engine)
            self.session = Session()
        else:
            self.engine = None
            self.session = None

        # Lineage graph
        self.lineage_graph = nx.DiGraph()

        # In-memory storage (if no database)
        self.versions_store: Dict[str, DataVersion] = {}
        self.events_store: Dict[str, LineageEvent] = {}

        self.logger = self._setup_logging()
        self._initialize_infrastructure()

    def _setup_logging(self) -> logging.Logger:
        """Setup comprehensive logging"""
        logger = logging.getLogger('VulnHunterDataLineageTracker')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _initialize_infrastructure(self):
        """Initialize GCS buckets and infrastructure"""
        buckets = [self.lineage_bucket, self.versions_bucket]

        for bucket_name in buckets:
            try:
                bucket = self.storage_client.bucket(bucket_name)
                if not bucket.exists():
                    bucket = self.storage_client.create_bucket(bucket_name, location=self.location)
                    self.logger.info(f"Created bucket: {bucket_name}")
            except Exception as e:
                self.logger.error(f"Error with bucket {bucket_name}: {e}")

    def create_dataset_version(self,
                             dataset_name: str,
                             data: pd.DataFrame,
                             version_number: Optional[str] = None,
                             parent_versions: List[str] = None,
                             metadata: Dict[str, Any] = None,
                             tags: List[str] = None) -> DataVersion:
        """
        Create a new version of a dataset with comprehensive tracking

        Args:
            dataset_name: Name of the dataset
            data: DataFrame containing the dataset
            version_number: Version number (auto-generated if None)
            parent_versions: List of parent version IDs
            metadata: Additional metadata
            tags: Tags for categorization

        Returns:
            DataVersion object
        """
        try:
            # Generate version information
            if version_number is None:
                existing_versions = self._get_dataset_versions(dataset_name)
                version_number = f"v{len(existing_versions) + 1:04d}"

            version_id = f"{dataset_name}_{version_number}_{uuid.uuid4().hex[:8]}"

            # Calculate checksum
            data_str = data.to_csv(index=False)
            checksum = hashlib.sha256(data_str.encode()).hexdigest()

            # Generate schema version
            schema_info = {
                'columns': list(data.columns),
                'dtypes': data.dtypes.to_dict(),
                'shape': data.shape
            }
            schema_str = json.dumps(schema_info, sort_keys=True)
            schema_version = hashlib.md5(schema_str.encode()).hexdigest()[:16]

            # Create version object
            version = DataVersion(
                version_id=version_id,
                dataset_name=dataset_name,
                version_number=version_number,
                creation_time=datetime.now(),
                checksum=checksum,
                size_bytes=len(data_str.encode()),
                record_count=len(data),
                schema_version=schema_version,
                parent_versions=parent_versions or [],
                metadata={
                    **(metadata or {}),
                    'schema_info': schema_info,
                    'data_types': {col: str(dtype) for col, dtype in data.dtypes.items()},
                    'null_counts': data.isnull().sum().to_dict(),
                    'unique_counts': data.nunique().to_dict()
                },
                tags=tags or []
            )

            # Store version data in GCS
            self._store_version_data(version, data)

            # Store version metadata
            self._store_version_metadata(version)

            # Record lineage event
            self._record_lineage_event(
                event_type=LineageEventType.DATASET_CREATED,
                source_datasets=parent_versions or [],
                target_datasets=[version_id],
                transformation="dataset_version_creation",
                parameters={
                    'version_number': version_number,
                    'record_count': len(data),
                    'schema_version': schema_version
                }
            )

            self.logger.info(f"Created dataset version: {version_id}")
            return version

        except Exception as e:
            self.logger.error(f"Error creating dataset version: {e}")
            raise

    def _store_version_data(self, version: DataVersion, data: pd.DataFrame):
        """Store version data in GCS"""
        try:
            blob_path = f"{version.dataset_name}/{version.version_number}/data.parquet"
            bucket = self.storage_client.bucket(self.versions_bucket)
            blob = bucket.blob(blob_path)

            # Store as parquet for efficiency
            parquet_data = data.to_parquet(index=False)
            blob.upload_from_string(parquet_data)

            self.logger.debug(f"Stored version data: {blob_path}")

        except Exception as e:
            self.logger.error(f"Error storing version data: {e}")
            raise

    def _store_version_metadata(self, version: DataVersion):
        """Store version metadata"""
        try:
            # Store in database if available
            if self.session:
                db_version = DataVersionModel(
                    version_id=version.version_id,
                    dataset_name=version.dataset_name,
                    version_number=version.version_number,
                    creation_time=version.creation_time,
                    checksum=version.checksum,
                    size_bytes=version.size_bytes,
                    record_count=version.record_count,
                    schema_version=version.schema_version,
                    parent_versions=version.parent_versions,
                    metadata=version.metadata,
                    tags=version.tags
                )
                self.session.add(db_version)
                self.session.commit()

            # Store in memory
            self.versions_store[version.version_id] = version

            # Store in GCS as backup
            metadata_path = f"{version.dataset_name}/{version.version_number}/metadata.json"
            bucket = self.storage_client.bucket(self.versions_bucket)
            blob = bucket.blob(metadata_path)
            blob.upload_from_string(json.dumps(asdict(version), default=str, indent=2))

        except Exception as e:
            self.logger.error(f"Error storing version metadata: {e}")
            raise

    def _record_lineage_event(self,
                            event_type: LineageEventType,
                            source_datasets: List[str],
                            target_datasets: List[str],
                            transformation: str,
                            parameters: Dict[str, Any] = None,
                            user: str = None,
                            execution_context: Dict[str, Any] = None):
        """Record a lineage event"""
        try:
            event = LineageEvent(
                event_id=f"{event_type.value}_{uuid.uuid4().hex[:16]}",
                event_type=event_type,
                timestamp=datetime.now(),
                source_datasets=source_datasets,
                target_datasets=target_datasets,
                transformation=transformation,
                parameters=parameters or {},
                user=user or "system",
                execution_context=execution_context or {}
            )

            # Store in database if available
            if self.session:
                db_event = LineageEventModel(
                    event_id=event.event_id,
                    event_type=event.event_type.value,
                    timestamp=event.timestamp,
                    source_datasets=event.source_datasets,
                    target_datasets=event.target_datasets,
                    transformation=event.transformation,
                    parameters=event.parameters,
                    user=event.user,
                    execution_context=event.execution_context
                )
                self.session.add(db_event)
                self.session.commit()

            # Store in memory
            self.events_store[event.event_id] = event

            # Update lineage graph
            self._update_lineage_graph(event)

            # Store in GCS
            self._store_lineage_event_gcs(event)

            self.logger.debug(f"Recorded lineage event: {event.event_id}")

        except Exception as e:
            self.logger.error(f"Error recording lineage event: {e}")
            raise

    def _update_lineage_graph(self, event: LineageEvent):
        """Update the lineage graph with new event"""
        try:
            # Add nodes for datasets
            for dataset in event.source_datasets + event.target_datasets:
                if not self.lineage_graph.has_node(dataset):
                    self.lineage_graph.add_node(dataset, dataset_id=dataset)

            # Add edges for lineage relationships
            for source in event.source_datasets:
                for target in event.target_datasets:
                    self.lineage_graph.add_edge(source, target, **{
                        'event_id': event.event_id,
                        'transformation': event.transformation,
                        'timestamp': event.timestamp.isoformat(),
                        'event_type': event.event_type.value
                    })

        except Exception as e:
            self.logger.error(f"Error updating lineage graph: {e}")

    def _store_lineage_event_gcs(self, event: LineageEvent):
        """Store lineage event in GCS"""
        try:
            event_path = f"events/{event.timestamp.strftime('%Y/%m/%d')}/{event.event_id}.json"
            bucket = self.storage_client.bucket(self.lineage_bucket)
            blob = bucket.blob(event_path)

            blob.upload_from_string(json.dumps(asdict(event), default=str, indent=2))

        except Exception as e:
            self.logger.error(f"Error storing lineage event in GCS: {e}")

    def get_dataset_version(self, version_id: str) -> Optional[DataVersion]:
        """Get a specific dataset version"""
        try:
            # Check memory first
            if version_id in self.versions_store:
                return self.versions_store[version_id]

            # Check database
            if self.session:
                db_version = self.session.query(DataVersionModel).filter_by(version_id=version_id).first()
                if db_version:
                    return DataVersion(
                        version_id=db_version.version_id,
                        dataset_name=db_version.dataset_name,
                        version_number=db_version.version_number,
                        creation_time=db_version.creation_time,
                        checksum=db_version.checksum,
                        size_bytes=db_version.size_bytes,
                        record_count=db_version.record_count,
                        schema_version=db_version.schema_version,
                        parent_versions=db_version.parent_versions,
                        metadata=db_version.metadata,
                        tags=db_version.tags
                    )

            return None

        except Exception as e:
            self.logger.error(f"Error getting dataset version: {e}")
            return None

    def _get_dataset_versions(self, dataset_name: str) -> List[DataVersion]:
        """Get all versions of a dataset"""
        try:
            versions = []

            if self.session:
                db_versions = self.session.query(DataVersionModel).filter_by(dataset_name=dataset_name).all()
                for db_version in db_versions:
                    version = DataVersion(
                        version_id=db_version.version_id,
                        dataset_name=db_version.dataset_name,
                        version_number=db_version.version_number,
                        creation_time=db_version.creation_time,
                        checksum=db_version.checksum,
                        size_bytes=db_version.size_bytes,
                        record_count=db_version.record_count,
                        schema_version=db_version.schema_version,
                        parent_versions=db_version.parent_versions,
                        metadata=db_version.metadata,
                        tags=db_version.tags
                    )
                    versions.append(version)
            else:
                # Use in-memory store
                versions = [v for v in self.versions_store.values() if v.dataset_name == dataset_name]

            return sorted(versions, key=lambda x: x.creation_time)

        except Exception as e:
            self.logger.error(f"Error getting dataset versions: {e}")
            return []

    def load_dataset_version(self, version_id: str) -> Optional[pd.DataFrame]:
        """Load data for a specific dataset version"""
        try:
            version = self.get_dataset_version(version_id)
            if not version:
                return None

            # Load from GCS
            blob_path = f"{version.dataset_name}/{version.version_number}/data.parquet"
            bucket = self.storage_client.bucket(self.versions_bucket)
            blob = bucket.blob(blob_path)

            if not blob.exists():
                self.logger.error(f"Version data not found: {blob_path}")
                return None

            # Download and load parquet
            parquet_data = blob.download_as_bytes()
            data = pd.read_parquet(pd.BytesIO(parquet_data))

            return data

        except Exception as e:
            self.logger.error(f"Error loading dataset version: {e}")
            return None

    def get_dataset_lineage(self, dataset_id: str, depth: int = 5) -> Dict[str, Any]:
        """Get lineage information for a dataset"""
        try:
            if not self.lineage_graph.has_node(dataset_id):
                return {'error': f'Dataset {dataset_id} not found in lineage graph'}

            # Get upstream lineage (sources)
            upstream_nodes = set()
            current_level = {dataset_id}

            for _ in range(depth):
                next_level = set()
                for node in current_level:
                    predecessors = set(self.lineage_graph.predecessors(node))
                    next_level.update(predecessors)
                    upstream_nodes.update(predecessors)

                if not next_level:
                    break
                current_level = next_level

            # Get downstream lineage (targets)
            downstream_nodes = set()
            current_level = {dataset_id}

            for _ in range(depth):
                next_level = set()
                for node in current_level:
                    successors = set(self.lineage_graph.successors(node))
                    next_level.update(successors)
                    downstream_nodes.update(successors)

                if not next_level:
                    break
                current_level = next_level

            # Build lineage subgraph
            lineage_nodes = upstream_nodes | downstream_nodes | {dataset_id}
            lineage_subgraph = self.lineage_graph.subgraph(lineage_nodes)

            # Convert to serializable format
            lineage_info = {
                'dataset_id': dataset_id,
                'upstream_datasets': list(upstream_nodes),
                'downstream_datasets': list(downstream_nodes),
                'lineage_graph': {
                    'nodes': [{'id': node, **self.lineage_graph.nodes[node]} for node in lineage_subgraph.nodes()],
                    'edges': [
                        {
                            'source': edge[0],
                            'target': edge[1],
                            **self.lineage_graph.edges[edge]
                        }
                        for edge in lineage_subgraph.edges()
                    ]
                },
                'depth_explored': depth
            }

            return lineage_info

        except Exception as e:
            self.logger.error(f"Error getting dataset lineage: {e}")
            return {'error': str(e)}

    def analyze_impact(self, dataset_id: str) -> Dict[str, Any]:
        """Analyze the impact of changes to a dataset"""
        try:
            lineage_info = self.get_dataset_lineage(dataset_id)

            if 'error' in lineage_info:
                return lineage_info

            downstream_datasets = lineage_info['downstream_datasets']

            # Analyze impact on downstream datasets
            impact_analysis = {
                'dataset_id': dataset_id,
                'directly_affected': len(downstream_datasets),
                'total_affected': len(downstream_datasets),
                'affected_datasets': downstream_datasets,
                'impact_levels': {},
                'recommendations': []
            }

            # Calculate impact levels
            for downstream_id in downstream_datasets:
                version = self.get_dataset_version(downstream_id)
                if version:
                    # Determine impact level based on various factors
                    impact_level = self._calculate_impact_level(dataset_id, downstream_id, version)
                    impact_analysis['impact_levels'][downstream_id] = impact_level

            # Generate recommendations
            impact_analysis['recommendations'] = self._generate_impact_recommendations(impact_analysis)

            return impact_analysis

        except Exception as e:
            self.logger.error(f"Error analyzing impact: {e}")
            return {'error': str(e)}

    def _calculate_impact_level(self, source_id: str, target_id: str, target_version: DataVersion) -> str:
        """Calculate impact level between datasets"""
        try:
            # Get edge information
            if self.lineage_graph.has_edge(source_id, target_id):
                edge_data = self.lineage_graph.edges[source_id, target_id]

                # Determine impact level based on transformation type and recency
                transformation = edge_data.get('transformation', '')
                event_timestamp = edge_data.get('timestamp', '')

                if transformation in ['dataset_merged', 'feature_extracted']:
                    return 'high'
                elif transformation in ['dataset_filtered', 'data_validated']:
                    return 'medium'
                else:
                    return 'low'
            else:
                return 'unknown'

        except Exception as e:
            self.logger.error(f"Error calculating impact level: {e}")
            return 'unknown'

    def _generate_impact_recommendations(self, impact_analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on impact analysis"""
        recommendations = []

        if impact_analysis['directly_affected'] > 10:
            recommendations.append("🔴 High impact change - consider staged rollout")

        if impact_analysis['directly_affected'] > 5:
            recommendations.append("⚠️ Medium impact - notify downstream users")

        # Check for high-impact downstream datasets
        high_impact_count = sum(1 for level in impact_analysis['impact_levels'].values() if level == 'high')
        if high_impact_count > 0:
            recommendations.append(f"🎯 {high_impact_count} high-impact downstream datasets require attention")

        if not recommendations:
            recommendations.append("✅ Low impact change - safe to proceed")

        return recommendations

    def compare_versions(self, version_id_1: str, version_id_2: str) -> Dict[str, Any]:
        """Compare two dataset versions"""
        try:
            version1 = self.get_dataset_version(version_id_1)
            version2 = self.get_dataset_version(version_id_2)

            if not version1 or not version2:
                return {'error': 'One or both versions not found'}

            comparison = {
                'version_1': {
                    'version_id': version1.version_id,
                    'version_number': version1.version_number,
                    'creation_time': version1.creation_time.isoformat(),
                    'record_count': version1.record_count,
                    'size_bytes': version1.size_bytes,
                    'checksum': version1.checksum
                },
                'version_2': {
                    'version_id': version2.version_id,
                    'version_number': version2.version_number,
                    'creation_time': version2.creation_time.isoformat(),
                    'record_count': version2.record_count,
                    'size_bytes': version2.size_bytes,
                    'checksum': version2.checksum
                },
                'differences': {
                    'record_count_diff': version2.record_count - version1.record_count,
                    'size_diff_bytes': version2.size_bytes - version1.size_bytes,
                    'schema_changed': version1.schema_version != version2.schema_version,
                    'identical_data': version1.checksum == version2.checksum
                },
                'schema_comparison': self._compare_schemas(version1.metadata.get('schema_info', {}),
                                                        version2.metadata.get('schema_info', {}))
            }

            return comparison

        except Exception as e:
            self.logger.error(f"Error comparing versions: {e}")
            return {'error': str(e)}

    def _compare_schemas(self, schema1: Dict[str, Any], schema2: Dict[str, Any]) -> Dict[str, Any]:
        """Compare schemas between two versions"""
        try:
            columns1 = set(schema1.get('columns', []))
            columns2 = set(schema2.get('columns', []))

            dtypes1 = schema1.get('dtypes', {})
            dtypes2 = schema2.get('dtypes', {})

            schema_comparison = {
                'added_columns': list(columns2 - columns1),
                'removed_columns': list(columns1 - columns2),
                'common_columns': list(columns1 & columns2),
                'dtype_changes': {}
            }

            # Check for dtype changes in common columns
            for col in schema_comparison['common_columns']:
                if col in dtypes1 and col in dtypes2 and dtypes1[col] != dtypes2[col]:
                    schema_comparison['dtype_changes'][col] = {
                        'old_type': dtypes1[col],
                        'new_type': dtypes2[col]
                    }

            return schema_comparison

        except Exception as e:
            self.logger.error(f"Error comparing schemas: {e}")
            return {'error': str(e)}

    def export_lineage_graph(self, format: str = "json") -> str:
        """Export the lineage graph"""
        try:
            if format == "json":
                graph_data = nx.node_link_data(self.lineage_graph)
                return json.dumps(graph_data, default=str, indent=2)
            elif format == "gexf":
                return '\n'.join(nx.generate_gexf(self.lineage_graph))
            else:
                raise ValueError(f"Unsupported format: {format}")

        except Exception as e:
            self.logger.error(f"Error exporting lineage graph: {e}")
            return f"Error: {str(e)}"

def main():
    """Demo usage of VulnHunterDataLineageTracker"""

    # Configuration
    PROJECT_ID = "your-gcp-project-id"
    LOCATION = "us-central1"

    # Initialize lineage tracker
    lineage_tracker = VulnHunterDataLineageTracker(
        project_id=PROJECT_ID,
        location=LOCATION
    )

    # Create sample datasets
    sample_data_v1 = pd.DataFrame({
        'code': ['def safe_func(): return True', 'system(user_input)', 'safe_code()'],
        'vulnerable': [0, 1, 0],
        'language': ['python', 'c', 'python']
    })

    sample_data_v2 = pd.DataFrame({
        'code': ['def safe_func(): return True', 'system(user_input)', 'safe_code()', 'new_vulnerable_code()'],
        'vulnerable': [0, 1, 0, 1],
        'language': ['python', 'c', 'python', 'java'],
        'severity': [0.0, 8.5, 0.0, 7.2]  # New column
    })

    try:
        print("🔗 VulnHunter Data Lineage & Versioning Demo")

        # Create first version
        print(f"\n📊 Creating dataset version 1...")
        version1 = lineage_tracker.create_dataset_version(
            dataset_name="vulnerability_samples",
            data=sample_data_v1,
            metadata={'source': 'manual_curation', 'quality': 'high'},
            tags=['curated', 'verified']
        )
        print(f"✅ Created version: {version1.version_id}")
        print(f"   Records: {version1.record_count}")
        print(f"   Schema version: {version1.schema_version}")

        # Create second version (evolution)
        print(f"\n📊 Creating dataset version 2 (with new column and records)...")
        version2 = lineage_tracker.create_dataset_version(
            dataset_name="vulnerability_samples",
            data=sample_data_v2,
            parent_versions=[version1.version_id],
            metadata={'source': 'automated_collection', 'quality': 'medium'},
            tags=['extended', 'automated']
        )
        print(f"✅ Created version: {version2.version_id}")
        print(f"   Records: {version2.record_count}")
        print(f"   Parent versions: {version2.parent_versions}")

        # Compare versions
        print(f"\n🔍 Comparing dataset versions...")
        comparison = lineage_tracker.compare_versions(version1.version_id, version2.version_id)
        print(f"✅ Version comparison:")
        print(f"   Record count difference: {comparison['differences']['record_count_diff']}")
        print(f"   Schema changed: {comparison['differences']['schema_changed']}")
        print(f"   Added columns: {comparison['schema_comparison']['added_columns']}")

        # Get dataset lineage
        print(f"\n🗺️ Analyzing dataset lineage...")
        lineage = lineage_tracker.get_dataset_lineage(version2.version_id)
        print(f"✅ Lineage analysis:")
        print(f"   Upstream datasets: {len(lineage.get('upstream_datasets', []))}")
        print(f"   Downstream datasets: {len(lineage.get('downstream_datasets', []))}")

        # Impact analysis
        print(f"\n🎯 Performing impact analysis...")
        impact = lineage_tracker.analyze_impact(version1.version_id)
        print(f"✅ Impact analysis:")
        print(f"   Directly affected datasets: {impact.get('directly_affected', 0)}")
        if impact.get('recommendations'):
            print(f"   Recommendations:")
            for rec in impact['recommendations']:
                print(f"     - {rec}")

        # Load specific version
        print(f"\n📥 Loading dataset version...")
        loaded_data = lineage_tracker.load_dataset_version(version2.version_id)
        if loaded_data is not None:
            print(f"✅ Successfully loaded version data:")
            print(f"   Shape: {loaded_data.shape}")
            print(f"   Columns: {list(loaded_data.columns)}")

        # Export lineage graph
        print(f"\n📤 Exporting lineage graph...")
        graph_json = lineage_tracker.export_lineage_graph(format="json")
        print(f"✅ Lineage graph exported (JSON format)")

        print(f"\n✅ Data lineage and versioning demo completed!")
        print(f"   🔄 Version control enabled")
        print(f"   🗺️ Lineage tracking active")
        print(f"   📊 Impact analysis available")
        print(f"   🔍 Version comparison tools ready")

    except Exception as e:
        print(f"❌ Error in demo: {e}")
        raise

if __name__ == "__main__":
    main()