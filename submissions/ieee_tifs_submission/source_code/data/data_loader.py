import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
import json
import os
from typing import Dict, List, Any
from transformers import AutoTokenizer

class VulnerabilityDataset(Dataset):
    def __init__(self, data_file: str, tokenizer, max_length: int = 512):
        self.data = pd.read_csv(data_file)
        self.tokenizer = tokenizer
        self.max_length = max_length
        
        # Vulnerability type mapping
        self.vuln_types = [
            'buffer_overflow', 'sql_injection', 'xss', 'command_injection',
            'path_traversal', 'auth_bypass', 'info_disclosure', 'csrf',
            'xxe', 'deserialization', 'race_condition', 'memory_corruption',
            'integer_overflow', 'format_string', 'weak_crypto', 'none'
        ]
        
        self.type_to_idx = {vuln_type: idx for idx, vuln_type in enumerate(self.vuln_types)}
    
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
        row = self.data.iloc[idx]
        
        # Tokenize code
        code = str(row['code'])  # Ensure it's string
        inputs = self.tokenizer(
            code,
            padding='max_length',
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt"
        )
        
        # Labels - ensure proper types
        is_vulnerable = 1.0 if row['vulnerability_type'] != 'none' else 0.0
        vuln_type = self.type_to_idx.get(str(row['vulnerability_type']), self.type_to_idx['none'])
        
        # Severity (simplified: high=1.0, medium=0.5, low=0.25, none=0.0)
        severity_map = {'high': 1.0, 'medium': 0.5, 'low': 0.25, 'none': 0.0}
        severity = severity_map.get(str(row.get('severity', 'none')), 0.0)
        
        return {
            'input_ids': inputs['input_ids'].squeeze().long(),  # Ensure long type
            'attention_mask': inputs['attention_mask'].squeeze().long(),
            'vulnerability_labels': torch.tensor(is_vulnerable, dtype=torch.float),
            'vuln_type_labels': torch.tensor(vuln_type, dtype=torch.long),
            'severity_labels': torch.tensor(severity, dtype=torch.float)
        }

class DataProcessor:
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.raw_dir = os.path.join(data_dir, "raw")
        self.processed_dir = os.path.join(data_dir, "processed")
    
    def create_enhanced_dataset(self):
        """Create a more comprehensive training dataset"""
        samples = []
        
        # Vulnerable samples with different patterns
        vulnerable_samples = [
            # Command Injection
            {
                'code': "os.system('ping ' + user_input)",
                'vulnerability_type': 'command_injection',
                'language': 'python',
                'severity': 'high'
            },
            {
                'code': "subprocess.call(user_input, shell=True)",
                'vulnerability_type': 'command_injection', 
                'language': 'python',
                'severity': 'high'
            },
            
            # SQL Injection
            {
                'code': "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
                'vulnerability_type': 'sql_injection',
                'language': 'python',
                'severity': 'high'
            },
            {
                'code': "db.query(f\"SELECT * FROM products WHERE name = '{product_name}'\")",
                'vulnerability_type': 'sql_injection',
                'language': 'python', 
                'severity': 'high'
            },
            
            # XSS
            {
                'code': "return '<div>' + user_content + '</div>'",
                'vulnerability_type': 'xss',
                'language': 'javascript',
                'severity': 'medium'
            },
            
            # Path Traversal
            {
                'code': "open('/var/www/' + filename, 'r')",
                'vulnerability_type': 'path_traversal',
                'language': 'python',
                'severity': 'medium'
            },
            
            # Buffer-related (C patterns)
            {
                'code': "strcpy(buffer, user_input);",
                'vulnerability_type': 'buffer_overflow',
                'language': 'c',
                'severity': 'high'
            },
            {
                'code': "gets(user_input);",
                'vulnerability_type': 'buffer_overflow',
                'language': 'c',
                'severity': 'high'
            }
        ]
        
        # Safe samples (non-vulnerable)
        safe_samples = [
            {
                'code': "subprocess.run(['ls', '-l'], capture_output=True)",
                'vulnerability_type': 'none',
                'language': 'python', 
                'severity': 'none'
            },
            {
                'code': "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                'vulnerability_type': 'none',
                'language': 'python',
                'severity': 'none'
            },
            {
                'code': "return '<div>' + escape(user_content) + '</div>'",
                'vulnerability_type': 'none',
                'language': 'javascript',
                'severity': 'none'
            },
            {
                'code': "open(os.path.join('/var/www/', safe_filename), 'r')",
                'vulnerability_type': 'none',
                'language': 'python',
                'severity': 'none'
            },
            {
                'code': "strncpy(buffer, user_input, sizeof(buffer)-1);",
                'vulnerability_type': 'none', 
                'language': 'c',
                'severity': 'none'
            }
        ]
        
        # Combine and save
        all_samples = vulnerable_samples + safe_samples
        df = pd.DataFrame(all_samples)
        
        # Save to CSV
        output_file = os.path.join(self.processed_dir, "enhanced_training_data.csv")
        df.to_csv(output_file, index=False)
        
        print(f"Created enhanced dataset with {len(df)} samples")
        return df

if __name__ == "__main__":
    processor = DataProcessor()
    df = processor.create_enhanced_dataset()
    print(df.head())
