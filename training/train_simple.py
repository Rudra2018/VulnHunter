#!/usr/bin/env python3

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np

def create_synthetic_data():
    """Create simple synthetic data for testing"""
    # Create random input data
    input_data = torch.randint(0, 1000, (100, 50))  # 100 samples, sequence length 50
    
    # Create labels: 50% vulnerable, 50% safe
    vuln_labels = torch.cat([torch.ones(50), torch.zeros(50)]).float()
    type_labels = torch.cat([torch.ones(50) * 5, torch.zeros(50)]).long()  # Type 5 = command_injection
    severity_labels = torch.cat([torch.ones(50) * 0.8, torch.zeros(50)]).float()
    
    # Create dataset
    dataset = TensorDataset(input_data, vuln_labels, type_labels, severity_labels)
    return dataset

def test_simple_training():
    """Test training with synthetic data"""
    print("Testing simple training pipeline...")
    
    # Create model
    from src.models.vuln_detector import SimpleVulnDetector
    config = {
        'vocab_size': 1000,
        'embedding_dim': 128,
        'num_classes': 16,
        'learning_rate': 0.001
    }
    model = SimpleVulnDetector(config)
    
    # Create synthetic data
    dataset = create_synthetic_data()
    train_loader = DataLoader(dataset, batch_size=8, shuffle=True)
    
    # Simple training loop
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.BCEWithLogitsLoss()
    
    model.train()
    for epoch in range(3):
        total_loss = 0
        for i, (input_ids, vuln_labels, type_labels, severity_labels) in enumerate(train_loader):
            optimizer.zero_grad()
            
            # Forward pass
            outputs = model(input_ids)
            loss = criterion(outputs['vulnerability'], vuln_labels)
            
            # Backward pass
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
            if i % 5 == 0:
                print(f'Epoch {epoch+1}, Batch {i}, Loss: {loss.item():.4f}')
        
        print(f'Epoch {epoch+1} completed. Average Loss: {total_loss/len(train_loader):.4f}')
    
    print("Simple training test completed successfully!")
    return True

if __name__ == "__main__":
    test_simple_training()
