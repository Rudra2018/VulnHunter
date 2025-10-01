#!/usr/bin/env python3

import os
import torch
from src.data.data_loader import DataProcessor
from src.models.vuln_detector import SimpleVulnDetector

def test_minimal():
    """Minimal test of the training pipeline"""
    print("Testing minimal training pipeline...")
    
    # Create dataset
    processor = DataProcessor()
    data_file = os.path.join("data", "processed", "enhanced_training_data.csv")
    
    if not os.path.exists(data_file):
        print("Creating dataset...")
        processor.create_enhanced_dataset()
    
    # Test model
    config = {
        'vocab_size': 10000,
        'embedding_dim': 256,
        'num_classes': 16,
        'learning_rate': 0.0001
    }
    
    model = SimpleVulnDetector(config)
    
    # Test forward pass
    sample_input = torch.randint(0, 10000, (2, 100))
    sample_mask = torch.ones(2, 100)
    output = model(input_ids=sample_input, attention_mask=sample_mask)
    
    print("Model test successful!")
    print(f"Input: {sample_input.shape}")
    print(f"Output - Vulnerability: {output['vulnerability'].shape}")
    print(f"Output - Type: {output['vuln_type'].shape}")
    print(f"Output - Severity: {output['severity'].shape}")
    
    # Test optimizer
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.0001)
    print("Optimizer test successful!")
    
    return True

def test_data_pipeline():
    """Test the complete data pipeline"""
    print("Testing data pipeline...")
    
    from src.data.data_loader import DataProcessor, VulnerabilityDataset
    from transformers import AutoTokenizer
    
    # Create dataset
    processor = DataProcessor()
    data_file = os.path.join("data", "processed", "enhanced_training_data.csv")
    
    if not os.path.exists(data_file):
        print("Creating enhanced dataset...")
        processor.create_enhanced_dataset()
    
    # Load tokenizer
    try:
        tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
    except:
        from transformers import BertTokenizer
        tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
    
    # Create dataset
    dataset = VulnerabilityDataset(data_file, tokenizer, max_length=256)
    
    print(f"Dataset created with {len(dataset)} samples")
    
    # Test one sample
    sample = dataset[0]
    print("Sample keys:", list(sample.keys()))
    print(f"Input IDs shape: {sample['input_ids'].shape}")
    print(f"Attention mask shape: {sample['attention_mask'].shape}")
    print(f"Vulnerability label: {sample['vulnerability_labels']}")
    print(f"Type label: {sample['vuln_type_labels']}")
    print(f"Severity label: {sample['severity_labels']}")
    
    return True

def test_training_components():
    """Test training components"""
    print("Testing training components...")
    
    from src.training.trainer import VulnTrainer
    
    # Create simple model and data
    config = {
        'vocab_size': 1000,
        'embedding_dim': 128,
        'num_classes': 16,
        'learning_rate': 0.001,
        'batch_size': 4
    }
    
    from src.models.vuln_detector import SimpleVulnDetector
    model = SimpleVulnDetector(config)
    
    # Create simple data
    from torch.utils.data import TensorDataset, DataLoader
    input_data = torch.randint(0, 1000, (16, 50))
    labels = torch.cat([torch.ones(8), torch.zeros(8)]).float()
    
    dataset = TensorDataset(input_data, labels, torch.zeros(16).long(), torch.zeros(16).float())
    train_loader = DataLoader(dataset, batch_size=4, shuffle=True)
    val_loader = DataLoader(dataset, batch_size=4, shuffle=False)
    
    # Test trainer initialization
    trainer = VulnTrainer(model, train_loader, val_loader, config)
    print("Trainer initialized successfully!")
    
    # Test one training step
    model.train()
    for batch in train_loader:
        input_ids, vuln_labels, type_labels, severity_labels = batch
        outputs = model(input_ids=input_ids)
        break
    
    print("Single training step successful!")
    
    return True

def main():
    """Run all tests"""
    print("Running Vulnerability Detection Pipeline Tests")
    print("=" * 50)
    
    tests = [
        ("Minimal Model Test", test_minimal),
        ("Data Pipeline Test", test_data_pipeline),
        ("Training Components Test", test_training_components),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        try:
            success = test_func()
            results.append((test_name, success))
            print(f"✅ {test_name} - PASSED")
        except Exception as e:
            results.append((test_name, False))
            print(f"❌ {test_name} - FAILED: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 50)
    print("Test Results Summary:")
    for test_name, success in results:
        status = "PASSED" if success else "FAILED"
        print(f"  {test_name}: {status}")
    
    all_passed = all(success for _, success in results)
    if all_passed:
        print("\n🎉 All tests passed! The pipeline is ready.")
    else:
        print(f"\n⚠️  {sum(1 for _, success in results if not success)} tests failed.")

if __name__ == "__main__":
    main()
