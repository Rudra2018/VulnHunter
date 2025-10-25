
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel
import numpy as np

class VulnHunterOmegaVHSInference:
    """Production inference for VulnHunter Ωmega + VHS"""
    
    def __init__(self, model_path):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
        
        # Load model (add full model class definitions here)
        checkpoint = torch.load(model_path, map_location=self.device)
        self.model = VulnHunterOmegaVHS(**checkpoint['model_config'])
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.to(self.device)
        self.model.eval()
        
    def analyze_code(self, code, file_path="unknown", commit_msg=""):
        """Analyze code for vulnerabilities with VHS classification"""
        
        # Preprocess inputs
        tokens = self.tokenizer(code, max_length=512, truncation=True, 
                               padding='max_length', return_tensors='pt')
        
        # Mock features (in production, use real feature extraction)
        graph_feats = torch.randn(1, 50)
        metadata_feats = torch.zeros(1, 10)
        
        # Create batch
        batch = {
            'graph_feats': graph_feats.to(self.device),
            'code_tokens': tokens['input_ids'].to(self.device),
            'attention_mask': tokens['attention_mask'].to(self.device),
            'metadata_feats': metadata_feats.to(self.device)
        }
        
        with torch.no_grad():
            outputs = self.model(batch)
            
            # Get predictions
            vul_prob = torch.softmax(outputs['logits'], dim=1)[0, 1].item()
            vhs_class = torch.argmax(outputs['vhs_probs'], dim=1)[0].item()
            
            class_names = ['Test', 'Academic', 'Production', 'Theoretical']
            
            return {
                'vulnerability_probability': vul_prob,
                'vhs_classification': class_names[vhs_class],
                'is_production_risk': vhs_class == 2,
                'mathematical_explanation': outputs['vhs_explanations']
            }

# Usage:
# analyzer = VulnHunterOmegaVHSInference('vulnhunter_omega_vhs_complete.pth')  # Uses best performing model
# result = analyzer.analyze_code("your_code_here")

# Alternative: Use the best model directly
# analyzer = VulnHunterOmegaVHSInference('vulnhunter_omega_vhs_best.pth')
# result = analyzer.analyze_code("your_code_here")
