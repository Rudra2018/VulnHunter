#!/usr/bin/env python3

import torch
from transformers import AutoTokenizer
from src.data.data_loader import DataProcessor, VulnerabilityDataset

def debug_token_ranges():
    """Debug token ranges to identify vocabulary size issues"""
    print("Debugging token ranges...")
    
    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    
    print(f"Tokenizer vocab size: {tokenizer.vocab_size}")
    print(f"Tokenizer model max length: {tokenizer.model_max_length}")
    
    # Create dataset
    processor = DataProcessor()
    data_file = "data/processed/enhanced_training_data.csv"
    
    if not os.path.exists(data_file):
        print("Creating dataset...")
        processor.create_enhanced_dataset()
    
    dataset = VulnerabilityDataset(data_file, tokenizer, max_length=256)
    
    # Check token ranges in the dataset
    all_input_ids = []
    for i in range(min(10, len(dataset))):  # Check first 10 samples
        sample = dataset[i]
        input_ids = sample['input_ids']
        all_input_ids.extend(input_ids.tolist())
        
        print(f"Sample {i}:")
        print(f"  Min token ID: {input_ids.min().item()}")
        print(f"  Max token ID: {input_ids.max().item()}")
        print(f"  Unique tokens: {len(torch.unique(input_ids))}")
    
    all_input_ids = torch.tensor(all_input_ids)
    print(f"\nOverall stats:")
    print(f"  Global min token ID: {all_input_ids.min().item()}")
    print(f"  Global max token ID: {all_input_ids.max().item()}")
    print(f"  Vocabulary size needed: {all_input_ids.max().item() + 1}")
    
    # Check if any tokens exceed typical vocabulary sizes
    vocab_sizes = {
        'CodeBERT': 50265,
        'BERT-base': 30522,
        'Our model': 10000
    }
    
    for name, size in vocab_sizes.items():
        tokens_above = (all_input_ids >= size).sum().item()
        print(f"  Tokens above {name} vocab size ({size}): {tokens_above}")

if __name__ == "__main__":
    import os
    debug_token_ranges()
