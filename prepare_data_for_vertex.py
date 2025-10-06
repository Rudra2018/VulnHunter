#!/usr/bin/env python3
"""
Prepare VulnHunter data for Vertex AI training
Converts local data to GCS-compatible format
"""

import torch
import json
import argparse
from pathlib import Path
from google.cloud import storage
import logging
from typing import List
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VertexDataPreparation:
    """Prepare and upload VulnHunter data to GCS"""

    def __init__(self, bucket_name: str, project_id: str = None):
        self.bucket_name = bucket_name
        self.project_id = project_id
        self.storage_client = storage.Client(project=project_id) if project_id else storage.Client()

    def prepare_and_upload(
        self,
        graph_data: List,
        code_texts: List[str],
        labels: List[int],
        data_prefix: str = 'vulnhunter',
        local_dir: str = '/tmp/vulnhunter_data'
    ):
        """
        Prepare and upload data to GCS

        Args:
            graph_data: List of PyG Data objects
            code_texts: List of code strings
            labels: List of labels (0=safe, 1=vulnerable)
            data_prefix: Prefix for data files
            local_dir: Temporary directory for local files
        """
        logger.info("=" * 80)
        logger.info("Preparing VulnHunter Data for Vertex AI")
        logger.info("=" * 80)

        # Validate inputs
        assert len(graph_data) == len(code_texts) == len(labels), \
            "graph_data, code_texts, and labels must have same length"

        logger.info(f"Total samples: {len(labels)}")
        logger.info(f"  Vulnerable: {sum(labels)} ({sum(labels)/len(labels)*100:.1f}%)")
        logger.info(f"  Safe: {len(labels) - sum(labels)} ({(len(labels)-sum(labels))/len(labels)*100:.1f}%)")

        # Create temporary directory
        temp_dir = Path(local_dir)
        temp_dir.mkdir(parents=True, exist_ok=True)

        # 1. Save graphs
        logger.info(f"\n[1/3] Saving {len(graph_data)} graphs...")
        graphs_path = temp_dir / f'{data_prefix}_graphs.pt'
        torch.save(graph_data, graphs_path)
        logger.info(f"  Saved to: {graphs_path}")
        logger.info(f"  Size: {graphs_path.stat().st_size / 1024 / 1024:.2f} MB")

        # 2. Save code texts
        logger.info(f"\n[2/3] Saving {len(code_texts)} code samples...")
        codes_path = temp_dir / f'{data_prefix}_codes.json'
        with open(codes_path, 'w') as f:
            json.dump(code_texts, f)
        logger.info(f"  Saved to: {codes_path}")
        logger.info(f"  Size: {codes_path.stat().st_size / 1024 / 1024:.2f} MB")

        # 3. Save labels
        logger.info(f"\n[3/3] Saving {len(labels)} labels...")
        labels_path = temp_dir / f'{data_prefix}_labels.json'
        with open(labels_path, 'w') as f:
            json.dump(labels, f)
        logger.info(f"  Saved to: {labels_path}")
        logger.info(f"  Size: {labels_path.stat().st_size / 1024:.2f} KB")

        # 4. Upload to GCS
        logger.info(f"\n[4/4] Uploading to gs://{self.bucket_name}/data/...")
        bucket = self.storage_client.bucket(self.bucket_name)

        for local_path in [graphs_path, codes_path, labels_path]:
            gcs_path = f'data/{local_path.name}'
            blob = bucket.blob(gcs_path)

            logger.info(f"  Uploading: {local_path.name} -> gs://{self.bucket_name}/{gcs_path}")
            blob.upload_from_filename(str(local_path))

            # Verify upload
            blob.reload()
            logger.info(f"    ✅ Size: {blob.size / 1024 / 1024:.2f} MB")

        logger.info("\n" + "=" * 80)
        logger.info("✅ Data upload complete!")
        logger.info("=" * 80)
        logger.info(f"GCS bucket: gs://{self.bucket_name}/data/")
        logger.info(f"Files:")
        logger.info(f"  - {data_prefix}_graphs.pt")
        logger.info(f"  - {data_prefix}_codes.json")
        logger.info(f"  - {data_prefix}_labels.json")

    def verify_upload(self, data_prefix: str = 'vulnhunter'):
        """Verify uploaded data exists and is valid"""
        logger.info("\nVerifying uploaded data...")

        bucket = self.storage_client.bucket(self.bucket_name)

        files = [
            f'data/{data_prefix}_graphs.pt',
            f'data/{data_prefix}_codes.json',
            f'data/{data_prefix}_labels.json'
        ]

        for gcs_path in files:
            blob = bucket.blob(gcs_path)
            if blob.exists():
                blob.reload()
                logger.info(f"  ✅ {gcs_path} ({blob.size / 1024 / 1024:.2f} MB)")
            else:
                logger.error(f"  ❌ {gcs_path} NOT FOUND")
                return False

        logger.info("✅ All files verified")
        return True


def load_example_data():
    """
    Example: Load your actual data here
    Replace this with your data loading logic
    """
    logger.info("Loading example data...")

    # TODO: Replace with your actual data loading
    # Example using HuggingFace dataset
    try:
        from core.huggingface_dataset_integrator import VulnGuardDatasetIntegrator
        from torch_geometric.data import Data
        import numpy as np

        integrator = VulnGuardDatasetIntegrator()

        if not integrator.load_all_datasets():
            logger.error("Failed to load datasets")
            return None, None, None

        processed_data = integrator.process_all_datasets()

        # Extract data
        graph_data = []
        code_texts = []
        labels = []

        for record in processed_data[:1000]:  # Limit for example
            code = record.get('code', '').strip()
            if len(code) < 10:
                continue

            # Create dummy graph (replace with actual graph construction)
            num_nodes = min(len(code.split()), 50)
            x = torch.randn(num_nodes, 128)  # Node features
            edge_index = torch.randint(0, num_nodes, (2, num_nodes * 2))  # Dummy edges

            graph = Data(x=x, edge_index=edge_index)

            graph_data.append(graph)
            code_texts.append(code)
            labels.append(record.get('vulnerable', 1))

        logger.info(f"Loaded {len(labels)} samples")
        return graph_data, code_texts, labels

    except Exception as e:
        logger.error(f"Error loading data: {e}")
        return None, None, None


def main():
    parser = argparse.ArgumentParser(description='Prepare VulnHunter data for Vertex AI')

    parser.add_argument('--project-id', type=str, required=True,
                       help='GCP Project ID')
    parser.add_argument('--bucket-name', type=str, required=True,
                       help='GCS bucket name (without gs:// prefix)')
    parser.add_argument('--data-prefix', type=str, default='vulnhunter',
                       help='Prefix for data files')
    parser.add_argument('--local-dir', type=str, default='/tmp/vulnhunter_data',
                       help='Temporary directory for local files')
    parser.add_argument('--verify-only', action='store_true',
                       help='Only verify existing upload')

    args = parser.parse_args()

    # Create data preparation handler
    prep = VertexDataPreparation(
        bucket_name=args.bucket_name,
        project_id=args.project_id
    )

    if args.verify_only:
        # Only verify
        prep.verify_upload(data_prefix=args.data_prefix)
        return

    # Load data
    logger.info("Step 1: Loading data...")
    graph_data, code_texts, labels = load_example_data()

    if graph_data is None:
        logger.error("❌ Failed to load data. Please implement load_example_data() with your data loading logic.")
        logger.info("\nTo use this script:")
        logger.info("1. Edit load_example_data() function")
        logger.info("2. Load your graph_data, code_texts, and labels")
        logger.info("3. Run: python prepare_data_for_vertex.py --project-id=PROJECT --bucket-name=BUCKET")
        sys.exit(1)

    # Prepare and upload
    logger.info("\nStep 2: Preparing and uploading to GCS...")
    prep.prepare_and_upload(
        graph_data=graph_data,
        code_texts=code_texts,
        labels=labels,
        data_prefix=args.data_prefix,
        local_dir=args.local_dir
    )

    # Verify
    logger.info("\nStep 3: Verifying upload...")
    prep.verify_upload(data_prefix=args.data_prefix)

    logger.info("\n✅ All done! Data ready for Vertex AI training.")
    logger.info(f"\nNext steps:")
    logger.info(f"1. Build container: gcloud builds submit --tag gcr.io/{args.project_id}/vulnhunter-trainer .")
    logger.info(f"2. Submit training: ./submit_job.sh")


if __name__ == "__main__":
    main()
