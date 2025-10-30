# VulnHunter Data Flow Diagrams

## Analysis Pipeline Flow

```mermaid
flowchart TD
    INPUT[Code Input] --> LANG_DETECT[Language Detection]
    LANG_DETECT --> PREPROCESS[Preprocessing & Tokenization]

    PREPROCESS --> FEATURE_EXT[Feature Extraction]

    FEATURE_EXT --> MATH_FEAT[Mathematical Features]
    FEATURE_EXT --> SEM_FEAT[Semantic Features]
    FEATURE_EXT --> STRUCT_FEAT[Structural Features]

    MATH_FEAT --> FUSION[Feature Fusion Layer]
    SEM_FEAT --> FUSION
    STRUCT_FEAT --> FUSION

    FUSION --> ENSEMBLE[Ensemble Analysis]

    ENSEMBLE --> LARGE_MODEL[Large Model Engine]
    ENSEMBLE --> DEEP_LEARN[Deep Learning Engine]
    ENSEMBLE --> PATTERN_MATCH[Pattern Matching]

    LARGE_MODEL --> CONFIDENCE[Confidence Engine]
    DEEP_LEARN --> CONFIDENCE
    PATTERN_MATCH --> CONFIDENCE

    CONFIDENCE --> EXPLAINABLE[Explainability Engine]
    EXPLAINABLE --> OUTPUT[Vulnerability Report]

    style INPUT fill:#4caf50
    style LANG_DETECT fill:#ff9800
    style FUSION fill:#9c27b0
    style CONFIDENCE fill:#f44336
    style OUTPUT fill:#2196f3
```

## Real-time Processing Flow

```mermaid
flowchart LR
    subgraph "File System Events"
        FILE_CREATE[File Created]
        FILE_MODIFY[File Modified]
        FILE_DELETE[File Deleted]
    end

    subgraph "Event Processing"
        FILTER[Event Filter]
        DEBOUNCE[Debouncing]
        QUEUE[Analysis Queue]
    end

    subgraph "Analysis Workers"
        WORKER1[Worker 1]
        WORKER2[Worker 2]
        WORKER3[Worker 3]
        WORKER4[Worker 4]
    end

    subgraph "Output Channels"
        WEBSOCKET[WebSocket]
        LOG_FILE[Log Files]
        ALERT_SYS[Alert System]
    end

    FILE_CREATE --> FILTER
    FILE_MODIFY --> FILTER
    FILE_DELETE --> FILTER

    FILTER --> DEBOUNCE
    DEBOUNCE --> QUEUE

    QUEUE --> WORKER1
    QUEUE --> WORKER2
    QUEUE --> WORKER3
    QUEUE --> WORKER4

    WORKER1 --> WEBSOCKET
    WORKER2 --> LOG_FILE
    WORKER3 --> ALERT_SYS
    WORKER4 --> WEBSOCKET

    style QUEUE fill:#ff9800
    style WORKER1 fill:#9c27b0
    style WORKER2 fill:#9c27b0
    style WORKER3 fill:#9c27b0
    style WORKER4 fill:#9c27b0
```

## Multi-Language Analysis Flow

```mermaid
flowchart TD
    CODE_INPUT[Source Code] --> LANG_ID{Language<br/>Identification}

    LANG_ID -->|.py| PYTHON[Python Analyzer]
    LANG_ID -->|.js/.ts| TYPESCRIPT[TypeScript/JS Analyzer]
    LANG_ID -->|.go| GO[Go Analyzer]
    LANG_ID -->|.rs| RUST[Rust Analyzer]
    LANG_ID -->|.java| JAVA[Java Analyzer]
    LANG_ID -->|.cpp/.c| CPP[C/C++ Analyzer]
    LANG_ID -->|.php| PHP[PHP Analyzer]

    subgraph "Language-Specific Analysis"
        PYTHON --> PY_PATTERNS[Python Vulnerability Patterns]
        TYPESCRIPT --> TS_PATTERNS[TypeScript/JS Patterns]
        GO --> GO_PATTERNS[Go Vulnerability Patterns]
        RUST --> RS_PATTERNS[Rust Safety Patterns]
        JAVA --> JAVA_PATTERNS[Java Security Patterns]
        CPP --> CPP_PATTERNS[C/C++ Buffer Patterns]
        PHP --> PHP_PATTERNS[PHP Injection Patterns]
    end

    PY_PATTERNS --> UNIFIED[Unified Vulnerability Format]
    TS_PATTERNS --> UNIFIED
    GO_PATTERNS --> UNIFIED
    RS_PATTERNS --> UNIFIED
    JAVA_PATTERNS --> UNIFIED
    CPP_PATTERNS --> UNIFIED
    PHP_PATTERNS --> UNIFIED

    UNIFIED --> SEVERITY[Severity Assessment]
    SEVERITY --> CWE_MAP[CWE Mapping]
    CWE_MAP --> REPORT[Final Report]

    style LANG_ID fill:#ff9800
    style UNIFIED fill:#9c27b0
    style REPORT fill:#4caf50
```

## Model Integration Flow

```mermaid
graph TB
    subgraph "Model Loading"
        LARGE_MODEL[Large Model<br/>1.5GB+]
        LITE_MODEL[Lite Model<br/>Fast Analysis]
        TRANSFORMER[Transformer Model<br/>CodeBERT]
    end

    subgraph "Analysis Modes"
        PRODUCTION[Production Mode]
        ENSEMBLE[Ensemble Mode]
        FAST[Fast Mode]
        RESEARCH[Research Mode]
    end

    subgraph "Processing Pipeline"
        TOKENIZER[Code Tokenization]
        EMBEDDINGS[Feature Embeddings]
        INFERENCE[Model Inference]
        POST_PROCESS[Post-processing]
    end

    LARGE_MODEL --> PRODUCTION
    LARGE_MODEL --> ENSEMBLE
    LITE_MODEL --> FAST
    TRANSFORMER --> RESEARCH

    PRODUCTION --> TOKENIZER
    ENSEMBLE --> TOKENIZER
    FAST --> TOKENIZER
    RESEARCH --> TOKENIZER

    TOKENIZER --> EMBEDDINGS
    EMBEDDINGS --> INFERENCE
    INFERENCE --> POST_PROCESS

    POST_PROCESS --> RESULTS[Analysis Results]

    style LARGE_MODEL fill:#f44336
    style LITE_MODEL fill:#4caf50
    style TRANSFORMER fill:#2196f3
    style RESULTS fill:#ff9800
```

## Error Handling Flow

```mermaid
flowchart TD
    ANALYSIS_START[Analysis Start] --> TRY_LARGE[Try Large Model]

    TRY_LARGE -->|Success| LARGE_RESULT[Large Model Result]
    TRY_LARGE -->|Memory Error| FALLBACK_LITE[Fallback to Lite Model]
    TRY_LARGE -->|Timeout| FALLBACK_PATTERN[Fallback to Pattern Matching]

    FALLBACK_LITE -->|Success| LITE_RESULT[Lite Model Result]
    FALLBACK_LITE -->|Error| FALLBACK_PATTERN

    FALLBACK_PATTERN -->|Success| PATTERN_RESULT[Pattern Match Result]
    FALLBACK_PATTERN -->|Error| BASIC_ANALYSIS[Basic Static Analysis]

    BASIC_ANALYSIS --> MINIMAL_RESULT[Minimal Result]

    LARGE_RESULT --> CONFIDENCE_CALC[Confidence Calculation]
    LITE_RESULT --> CONFIDENCE_CALC
    PATTERN_RESULT --> CONFIDENCE_CALC
    MINIMAL_RESULT --> CONFIDENCE_CALC

    CONFIDENCE_CALC --> FINAL_REPORT[Final Report with Confidence]

    style TRY_LARGE fill:#2196f3
    style FALLBACK_LITE fill:#ff9800
    style FALLBACK_PATTERN fill:#f44336
    style FINAL_REPORT fill:#4caf50
```

## Performance Monitoring Flow

```mermaid
sequenceDiagram
    participant USER as User
    participant API as API Server
    participant MONITOR as Performance Monitor
    participant METRICS as Metrics Store
    participant ALERT as Alert System

    USER->>API: Analysis Request
    API->>MONITOR: Start Performance Tracking

    MONITOR->>MONITOR: Record Start Time
    MONITOR->>MONITOR: Monitor Memory Usage
    MONITOR->>MONITOR: Track CPU Usage

    API->>API: Perform Analysis

    API->>MONITOR: Analysis Complete
    MONITOR->>MONITOR: Calculate Metrics

    MONITOR->>METRICS: Store Performance Data

    alt Performance Threshold Exceeded
        MONITOR->>ALERT: Trigger Alert
        ALERT->>USER: Performance Warning
    end

    API->>USER: Analysis Results + Performance Stats
```