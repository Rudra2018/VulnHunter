
FROM gcr.io/deeplearning-platform-release/pytorch-gpu.1-13

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python3", "distributed_training.py"]
        