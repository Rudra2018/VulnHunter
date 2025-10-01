#!/usr/bin/env python3

import torch
from transformers import AutoTokenizer
from src.models.vuln_detector import SimpleVulnDetector

def test_fixed_model():
    """Test the model with fixed vocabulary size"""
    print("Testing fixed model...")
    
    # Load tokenizer to get correct vocab size
    tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
    vocab_size = tokenizer.vocab_size
    
    print(f"Using vocabulary size: {vocab_size}")
    
    # Create model with correct vocab size
    config = {
        'vocab_size': vocab_size,  # Use actual tokenizer vocab size
        'embedding_dim': 256,
        'num_classes': 16
    }
    
    model = SimpleVulnDetector(config)
    
    # Test with actual tokenized input
    sample_code = ["os.system('test')", "print('hello')"]
    inputs = tokenizer(
        sample_code,
        padding='max_length',
        truncation=True,
        max_length=256,
        return_tensors="pt"
    )
    
    print(f"Input IDs shape: {inputs['input_ids'].shape}")
    print(f"Input IDs range: {inputs['input_ids'].min()} to {inputs['input_ids'].max()}")
    
    # Test forward pass
    try:
        with torch.no_grad():
            outputs = model(
                input_ids=inputs['input_ids'],
                attention_mask=inputs['attention_mask']
            )
        
        print("✅ Forward pass successful!")
        print(f"Vulnerability output: {outputs['vulnerability'].shape}")
        print(f"Type output: {outputs['vuln_type'].shape}")
        print(f"Severity output: {outputs['severity'].shape}")
        return True
        
    except Exception as e:
        print(f"❌ Forward pass failed: {e}")
        return False

if __name__ == "__main__":
    test_fixed_model()
