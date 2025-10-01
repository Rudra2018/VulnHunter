#!/usr/bin/env python3

import os
import yaml
import argparse
import torch
from sklearn.model_selection import train_test_split

def load_config():
    """Load configuration from YAML file"""
    try:
        with open('config/settings.yaml', 'r') as f:
            config = yaml.safe_load(f)
        
        # Ensure numeric values are properly typed
        if 'model' in config:
            if 'learning_rate' in config['model']:
                config['model']['learning_rate'] = float(config['model']['learning_rate'])
            if 'batch_size' in config['model']:
                config['model']['batch_size'] = int(config['model']['batch_size'])
            if 'epochs' in config['model']:
                config['model']['epochs'] = int(config['model']['epochs'])
            if 'num_classes' in config['model']:
                config['model']['num_classes'] = int(config['model']['num_classes'])
            if 'max_sequence_length' in config['model']:
                config['model']['max_sequence_length'] = int(config['model']['max_sequence_length'])
        
        return config
    except FileNotFoundError:
        print("Warning: config/settings.yaml not found. Using default configuration.")
        return get_default_config()
    except Exception as e:
        print(f"Error loading config: {e}")
        return get_default_config()

def get_default_config():
    """Return default configuration if YAML file is not found"""
    return {
        'model': {
            'code_bert_model': 'microsoft/codebert-base',
            'hidden_size': 768,
            'num_classes': 16,
            'learning_rate': 0.00002,
            'batch_size': 8,
            'epochs': 10,
            'max_sequence_length': 256,
            'vocab_size': 50265,  # CodeBERT vocab size
            'embedding_dim': 256
        },
        'data': {
            'supported_languages': ['python', 'java', 'c', 'cpp', 'javascript', 'go'],
            'train_test_split': 0.8,
            'validation_split': 0.2
        },
        'training': {
            'early_stopping_patience': 5,
            'save_best_only': True,
            'log_interval': 10
        },
        'vulnerability_types': [
            'buffer_overflow', 'sql_injection', 'xss', 'command_injection',
            'path_traversal', 'auth_bypass', 'info_disclosure', 'csrf',
            'xxe', 'deserialization', 'race_condition', 'memory_corruption',
            'integer_overflow', 'format_string', 'weak_crypto', 'none'
        ]
    }

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Detection ML Research")
    parser.add_argument('--mode', choices=['parse', 'collect', 'train', 'test', 'evaluate', 'demo'], required=True,
                       help='Operation mode: parse, collect, train, test, evaluate, or demo')
    parser.add_argument('--input', help='Input file or directory')
    parser.add_argument('--output', help='Output directory or file')
    parser.add_argument('--epochs', type=int, default=10, help='Number of training epochs')
    parser.add_argument('--model_path', help='Path to saved model for evaluation')
    parser.add_argument('--threshold', type=float, default=0.5, help='Confidence threshold for predictions')
    
    args = parser.parse_args()
    config = load_config()
    
    # Create necessary directories
    os.makedirs('models/saved_models', exist_ok=True)
    os.makedirs('results', exist_ok=True)
    os.makedirs('data/processed', exist_ok=True)
    
    if args.mode == 'parse':
        from src.data.multi_parser import MultiFormatParser
        
        if not args.input:
            print("Please provide input file with --input")
            return
        
        if not os.path.exists(args.input):
            print(f"Input file not found: {args.input}")
            return
        
        parser = MultiFormatParser(config)
        result = parser.parse_file(args.input)
        
        print(f"Parsed {args.input}:")
        print(f"File type: {result.get('file_type', 'unknown')}")
        print(f"Features extracted: {len(result)}")
        
        if 'error' in result:
            print(f"Error during parsing: {result['error']}")
        
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"Results saved to {args.output}")
        else:
            # Print summary
            if 'functions' in result:
                print(f"Functions found: {len(result['functions'])}")
            if 'classes' in result:
                print(f"Classes found: {len(result['classes'])}")
            if 'imports' in result:
                print(f"Imports found: {len(result['imports'])}")
    
    elif args.mode == 'collect':
        from src.data.dataset_collector import DatasetCollector
        from src.data.data_loader import DataProcessor
        
        print("Collecting training data...")
        collector = DatasetCollector()
        df = collector.create_training_samples()
        print(f"Collected {len(df)} training samples")
        
        # Also create enhanced dataset
        processor = DataProcessor()
        enhanced_df = processor.create_enhanced_dataset()
        print(f"Created enhanced dataset with {len(enhanced_df)} samples")
        
        if args.output:
            enhanced_df.to_csv(args.output, index=False)
            print(f"Enhanced dataset saved to {args.output}")
    
    elif args.mode == 'train':
        print("Setting up training pipeline...")
        try:
            from src.data.data_loader import DataProcessor, VulnerabilityDataset
            from src.models.vuln_detector import SimpleVulnDetector
            from src.training.trainer import VulnTrainer
            
            # Setup training
            processor = DataProcessor()
            data_file = os.path.join("data", "processed", "enhanced_training_data.csv")
            
            if not os.path.exists(data_file):
                print("Creating enhanced training dataset...")
                processor.create_enhanced_dataset()
            
            # Load tokenizer
            from transformers import AutoTokenizer
            try:
                tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
                if tokenizer.pad_token is None:
                    tokenizer.pad_token = tokenizer.eos_token
                print("Loaded CodeBERT tokenizer successfully.")
                print(f"Tokenizer vocab size: {tokenizer.vocab_size}")
            except Exception as e:
                print(f"Warning: Could not load CodeBERT tokenizer: {e}")
                from transformers import BertTokenizer
                tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
                print("Using fallback BERT tokenizer.")
            
            # Create dataset
            dataset = VulnerabilityDataset(data_file, tokenizer, max_length=config['model']['max_sequence_length'])
            print(f"Dataset loaded with {len(dataset)} samples.")
            
            # Split dataset
            train_size = int(0.8 * len(dataset))
            val_size = len(dataset) - train_size
            train_dataset, val_dataset = torch.utils.data.random_split(dataset, [train_size, val_size])
            
            # Create data loaders
            batch_size = config['model']['batch_size']
            train_loader = torch.utils.data.DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
            val_loader = torch.utils.data.DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
            
            # Update config for simple model - USE CORRECT VOCAB SIZE
            model_config = config['model'].copy()
            model_config['vocab_size'] = tokenizer.vocab_size  # Use tokenizer's actual vocab size
            model_config['embedding_dim'] = 256
            
            # Create model
            model = SimpleVulnDetector(model_config)
            print(f"Model created with {sum(p.numel() for p in model.parameters())} parameters.")
            print(f"Training samples: {len(train_loader.dataset)}")
            print(f"Validation samples: {len(val_loader.dataset)}")
            
            # Initialize trainer
            trainer = VulnTrainer(model, train_loader, val_loader, config['model'])
            
            # Train model
            trainer.train(epochs=args.epochs)
            
            # Save model
            model_path = args.output or "models/saved_models/vuln_detector.pth"
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            trainer.save_model(model_path)
            
            # Plot training history
            plot_path = model_path.replace('.pth', '_training.png')
            trainer.plot_training_history(plot_path)
            
            print("Training completed successfully!")
            print(f"Model saved to: {model_path}")
            print(f"Training plot saved to: {plot_path}")
            
        except Exception as e:
            print(f"Error during training: {e}")
            import traceback
            traceback.print_exc()
    
    elif args.mode == 'evaluate':
        if not args.model_path:
            print("Please provide model path with --model_path")
            return
        
        if not os.path.exists(args.model_path):
            print(f"Model file not found: {args.model_path}")
            return
        
        try:
            from src.models.vuln_detector import SimpleVulnDetector
            from src.training.trainer import evaluate_model
            from src.data.data_loader import DataProcessor, VulnerabilityDataset
            
            # Load model
            print(f"Loading model from {args.model_path}...")
            checkpoint = torch.load(args.model_path, map_location='cpu')
            model_config = checkpoint.get('config', config['model'])
            model = SimpleVulnDetector(model_config)
            model.load_state_dict(checkpoint['model_state_dict'])
            print("Model loaded successfully.")
            
            # Setup data
            processor = DataProcessor()
            data_file = os.path.join("data", "processed", "enhanced_training_data.csv")
            
            if not os.path.exists(data_file):
                print("Creating enhanced training dataset...")
                processor.create_enhanced_dataset()
            
            from transformers import AutoTokenizer
            tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            
            dataset = VulnerabilityDataset(data_file, tokenizer, max_length=config['model']['max_sequence_length'])
            _, _, val_dataset = torch.utils.data.random_split(dataset, [0, 0, len(dataset)])
            val_loader = torch.utils.data.DataLoader(val_dataset, batch_size=config['model']['batch_size'], shuffle=False)
            
            # Evaluate
            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            model.to(device)
            
            print("Evaluating on validation set...")
            results = evaluate_model(model, val_loader, device)
            
            # Save results
            if args.output:
                import json
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"Results saved to {args.output}")
            else:
                print("\nEvaluation Results:")
                for metric, value in results.items():
                    if metric != 'confusion_matrix' and metric != 'predictions' and metric != 'labels' and metric != 'probabilities':
                        print(f"  {metric}: {value:.4f}")
                    
        except Exception as e:
            print(f"Error during evaluation: {e}")
            import traceback
            traceback.print_exc()
    
    elif args.mode == 'demo':
        """Demo mode - show predictions on sample code"""
        print("Running demo mode...")
        
        # Sample code snippets for demonstration
        sample_code = [
            "os.system('rm -rf /')",  # Dangerous command injection
            "print('Hello World')",   # Safe code
            "cursor.execute('SELECT * FROM users WHERE id = ' + user_input)",  # SQL injection
            "subprocess.run(['ls', '-l'], capture_output=True)",  # Safe
            "eval(user_input)",  # Code injection
            "open('/etc/passwd', 'r')",  # Path traversal
        ]
        
        print("Sample code snippets:")
        for i, code in enumerate(sample_code):
            print(f"  {i+1}. {code}")
        
        print("\nNote: For full predictions, train a model first and use evaluate mode.")
    
    elif args.mode == 'test':
        print("Testing model architecture...")
        try:
            from src.models.vuln_detector import test_model
            test_model()
            print("Model test completed successfully!")
        except Exception as e:
            print(f"Error during model test: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
