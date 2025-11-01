
# VulnHunter Ωmega Deployment Script
import torch
import pickle
import json

# Load model
checkpoint = torch.load('vulnhunter_omega_v3.pth', map_location='cpu')
model_info = checkpoint['model_info']

# Initialize model architecture
model = VulnHunterTransformer(
    vocab_size=model_info['model_params']['vocab_size'],
    embed_dim=model_info['model_params']['embed_dim'],
    num_heads=model_info['model_params']['num_heads'],
    num_layers=model_info['model_params']['num_layers'],
    max_seq_len=model_info['model_params']['max_seq_len']
)

# Load weights
model.load_state_dict(checkpoint['model_state_dict'])
model.eval()

# Load tokenizer
with open('vulnhunter_tokenizer.pkl', 'rb') as f:
    tokenizer = pickle.load(f)

print("🚀 VulnHunter Ωmega loaded successfully!")
print(f"📊 F1-Score: {model_info['performance']['f1_score']:.4f}")
