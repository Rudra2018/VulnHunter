#!/bin/bash
#
# VulnHunter Complete Deployment to Vertex AI
# This script automates the entire deployment process
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration (EDIT THESE)
PROJECT_ID="${PROJECT_ID:-your-project-id}"  # Replace with your project ID
REGION="${REGION:-us-central1}"
BUCKET_NAME="${BUCKET_NAME:-${PROJECT_ID}-vulnhunter}"
DATA_PREFIX="${DATA_PREFIX:-vulnhunter}"
RUN_NAME="run-$(date +%Y%m%d-%H%M%S)"

# Container configuration
IMAGE_NAME="vulnhunter-trainer"
IMAGE_TAG="latest"
IMAGE_URI="gcr.io/${PROJECT_ID}/${IMAGE_NAME}:${IMAGE_TAG}"

# Machine configuration
MACHINE_TYPE="${MACHINE_TYPE:-n1-standard-8}"
GPU_TYPE="${GPU_TYPE:-NVIDIA_TESLA_T4}"
GPU_COUNT="${GPU_COUNT:-1}"

# Training configuration
HIDDEN_DIM="${HIDDEN_DIM:-256}"
NUM_HEADS="${NUM_HEADS:-8}"
DROPOUT="${DROPOUT:-0.3}"
GNN_EPOCHS="${GNN_EPOCHS:-100}"
CODEBERT_EPOCHS="${CODEBERT_EPOCHS:-10}"
BATCH_SIZE="${BATCH_SIZE:-32}"
LEARNING_RATE="${LEARNING_RATE:-0.001}"
GRADIENT_ACCUMULATION="${GRADIENT_ACCUMULATION:-4}"

echo "=============================================="
echo "  VulnHunter Vertex AI Deployment"
echo "=============================================="
echo ""
echo "Configuration:"
echo "  Project ID: $PROJECT_ID"
echo "  Region: $REGION"
echo "  Bucket: gs://$BUCKET_NAME"
echo "  Run Name: $RUN_NAME"
echo "  Machine: $MACHINE_TYPE"
echo "  GPU: ${GPU_COUNT}x $GPU_TYPE"
echo ""

# Check if user wants to proceed
read -p "Continue with deployment? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_warning "Deployment cancelled"
    exit 0
fi

# Step 1: Setup GCP project
log_info "Step 1/7: Setting up GCP project..."

gcloud config set project $PROJECT_ID

log_info "Enabling required APIs..."
gcloud services enable aiplatform.googleapis.com \
    compute.googleapis.com \
    storage.googleapis.com \
    containerregistry.googleapis.com \
    cloudbuild.googleapis.com

log_success "APIs enabled"

# Step 2: Create GCS bucket if it doesn't exist
log_info "Step 2/7: Setting up GCS bucket..."

if gsutil ls -b gs://$BUCKET_NAME > /dev/null 2>&1; then
    log_success "Bucket gs://$BUCKET_NAME already exists"
else
    log_info "Creating bucket gs://$BUCKET_NAME..."
    gsutil mb -l $REGION gs://$BUCKET_NAME
    log_success "Bucket created"
fi

# Step 3: Prepare and upload data
log_info "Step 3/7: Preparing and uploading data..."

# Check if data preparation script exists
if [ -f "prepare_data_for_vertex.py" ]; then
    log_info "Running data preparation script..."
    python prepare_data_for_vertex.py \
        --project-id $PROJECT_ID \
        --bucket-name $BUCKET_NAME \
        --data-prefix $DATA_PREFIX

    log_success "Data uploaded to GCS"
else
    log_warning "prepare_data_for_vertex.py not found"
    log_warning "Please prepare your data manually and upload to:"
    log_warning "  gs://$BUCKET_NAME/data/${DATA_PREFIX}_graphs.pt"
    log_warning "  gs://$BUCKET_NAME/data/${DATA_PREFIX}_codes.json"
    log_warning "  gs://$BUCKET_NAME/data/${DATA_PREFIX}_labels.json"

    read -p "Have you uploaded the data? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_error "Data not ready. Exiting."
        exit 1
    fi
fi

# Verify data upload
log_info "Verifying data files..."
DATA_FILES=(
    "data/${DATA_PREFIX}_graphs.pt"
    "data/${DATA_PREFIX}_codes.json"
    "data/${DATA_PREFIX}_labels.json"
)

for file in "${DATA_FILES[@]}"; do
    if gsutil ls gs://$BUCKET_NAME/$file > /dev/null 2>&1; then
        log_success "  ✓ $file"
    else
        log_error "  ✗ $file NOT FOUND"
        exit 1
    fi
done

# Step 4: Build and push container
log_info "Step 4/7: Building training container..."
log_info "This may take 5-10 minutes..."

if [ -f "Dockerfile.vertex" ]; then
    log_info "Building container with Cloud Build..."
    gcloud builds submit --tag $IMAGE_URI --timeout=20m .
    log_success "Container built: $IMAGE_URI"
else
    log_error "Dockerfile.vertex not found"
    exit 1
fi

# Step 5: Submit training job
log_info "Step 5/7: Submitting training job..."

JOB_NAME="vulnhunter-${RUN_NAME}"

log_info "Job configuration:"
log_info "  Name: $JOB_NAME"
log_info "  GNN Epochs: $GNN_EPOCHS"
log_info "  CodeBERT Epochs: $CODEBERT_EPOCHS"
log_info "  Batch Size: $BATCH_SIZE"
log_info "  Hidden Dim: $HIDDEN_DIM"

# Submit job using Python SDK
if [ -f "submit_vertex_job.py" ]; then
    python submit_vertex_job.py \
        --project-id $PROJECT_ID \
        --region $REGION \
        --bucket-name $BUCKET_NAME \
        --container-uri $IMAGE_URI \
        --job-name $JOB_NAME \
        --machine-type $MACHINE_TYPE \
        --gpu-type $GPU_TYPE \
        --gpu-count $GPU_COUNT \
        --data-prefix $DATA_PREFIX \
        --run-name $RUN_NAME \
        --hidden-dim $HIDDEN_DIM \
        --num-heads $NUM_HEADS \
        --dropout $DROPOUT \
        --gnn-epochs $GNN_EPOCHS \
        --codebert-epochs $CODEBERT_EPOCHS \
        --batch-size $BATCH_SIZE \
        --learning-rate $LEARNING_RATE \
        --gradient-accumulation $GRADIENT_ACCUMULATION

    log_success "Training job submitted"
else
    # Fallback to gcloud CLI
    log_info "Using gcloud CLI to submit job..."

    gcloud ai custom-jobs create \
        --region=$REGION \
        --display-name=$JOB_NAME \
        --worker-pool-spec=machine-type=$MACHINE_TYPE,replica-count=1,accelerator-type=$GPU_TYPE,accelerator-count=$GPU_COUNT,container-image-uri=$IMAGE_URI \
        --args="--project-id=$PROJECT_ID,--bucket-name=$BUCKET_NAME,--data-prefix=$DATA_PREFIX,--run-name=$RUN_NAME,--hidden-dim=$HIDDEN_DIM,--num-heads=$NUM_HEADS,--dropout=$DROPOUT,--gnn-epochs=$GNN_EPOCHS,--codebert-epochs=$CODEBERT_EPOCHS,--batch-size=$BATCH_SIZE,--learning-rate=$LEARNING_RATE,--gradient-accumulation=$GRADIENT_ACCUMULATION"

    log_success "Training job submitted"
fi

# Step 6: Provide monitoring instructions
log_info "Step 6/7: Monitoring setup..."

echo ""
echo "=============================================="
echo "  🚀 Training Job Submitted!"
echo "=============================================="
echo ""
echo "Monitor your training job:"
echo ""
echo "1. Console UI:"
echo "   https://console.cloud.google.com/vertex-ai/training/custom-jobs?project=$PROJECT_ID"
echo ""
echo "2. Stream logs (CLI):"
echo "   gcloud ai custom-jobs stream-logs $JOB_NAME --region=$REGION"
echo ""
echo "3. List all jobs:"
echo "   python submit_vertex_job.py --project-id=$PROJECT_ID --region=$REGION --bucket-name=$BUCKET_NAME --list-jobs"
echo ""

# Step 7: Provide next steps
log_info "Step 7/7: Next steps..."

echo ""
echo "What happens next:"
echo ""
echo "1. Training will take approximately 6-8 hours with T4 GPU"
echo "2. Models will be saved to: gs://$BUCKET_NAME/models/$RUN_NAME/"
echo "3. Results will include:"
echo "   - GNN model (best_gnn_model.pth)"
echo "   - CodeBERT model (codebert_vuln/)"
echo "   - Ensemble config (ensemble_config.pkl)"
echo "   - Training results (results.json)"
echo "   - Threshold analysis (threshold_analysis.png)"
echo ""
echo "After training completes:"
echo ""
echo "1. Download models:"
echo "   gsutil -m cp -r gs://$BUCKET_NAME/models/$RUN_NAME/ ./trained_models/"
echo ""
echo "2. View results:"
echo "   gsutil cat gs://$BUCKET_NAME/models/$RUN_NAME/results.json"
echo ""
echo "3. Deploy for inference (optional)"
echo ""

# Estimated cost
HOURS=7
T4_COST_PER_HOUR=0.35
CPU_COST_PER_HOUR=0.38
STORAGE_COST=0.50
TOTAL_COST=$(echo "$HOURS * ($T4_COST_PER_HOUR + $CPU_COST_PER_HOUR) + $STORAGE_COST" | bc)

echo "Estimated cost for this training run:"
echo "  GPU ($GPU_TYPE): \$$(echo "$HOURS * $T4_COST_PER_HOUR" | bc) (~$HOURS hours)"
echo "  CPU ($MACHINE_TYPE): \$$(echo "$HOURS * $CPU_COST_PER_HOUR" | bc)"
echo "  Storage: \$$STORAGE_COST"
echo "  Total: ~\$$TOTAL_COST"
echo ""

log_success "Deployment complete!"

# Optional: Stream logs
echo ""
read -p "Would you like to stream logs now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "Streaming logs (Ctrl+C to stop)..."
    gcloud ai custom-jobs stream-logs $JOB_NAME --region=$REGION
fi
