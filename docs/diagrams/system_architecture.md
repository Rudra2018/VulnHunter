# VulnHunter Ω System Architecture

## Overall System Architecture

```mermaid
graph TB
    subgraph "User Interface Layer"
        CLI[CLI Tool]
        API[REST API]
        WS[WebSocket Real-time]
    end

    subgraph "Analysis Layer"
        RT[Real-time Monitor]
        DL[Deep Learning Analyzer]
        ML[Multi-Language Analyzer]
        PROD[Production Platform]
    end

    subgraph "Core Engines"
        MATH[Mathematical Engine]
        LM[Large Model Engine]
        TRANS[Transformer Engine]
        CONF[Confidence Engine]
    end

    subgraph "Integration Layer"
        VALID[Validation Framework]
        INTEG[Model Integration]
        EXPL[Explainability Engine]
    end

    subgraph "Data Layer"
        MODELS[(Model Storage)]
        CONFIG[(Configuration)]
        LOGS[(Logs & Results)]
    end

    CLI --> RT
    CLI --> DL
    CLI --> ML
    API --> PROD
    WS --> RT

    RT --> MATH
    DL --> LM
    DL --> TRANS
    ML --> CONF
    PROD --> INTEG

    MATH --> VALID
    LM --> INTEG
    TRANS --> INTEG
    CONF --> EXPL

    VALID --> MODELS
    INTEG --> CONFIG
    EXPL --> LOGS

    style CLI fill:#e1f5fe
    style API fill:#e1f5fe
    style WS fill:#e1f5fe
    style RT fill:#f3e5f5
    style DL fill:#f3e5f5
    style ML fill:#f3e5f5
    style MATH fill:#e8f5e8
    style LM fill:#e8f5e8
    style TRANS fill:#e8f5e8
    style CONF fill:#e8f5e8
```

## Component Architecture

```mermaid
graph LR
    subgraph "Core Components"
        A[Math Engine<br/>24-Layer Framework]
        B[Production Platform<br/>Unified Interface]
        C[Confidence Engine<br/>FP Reduction]
        D[Explainability<br/>Visual Analysis]
    end

    subgraph "Analysis Engines"
        E[Large Model<br/>1.5GB+ Support]
        F[Transformer<br/>CodeBERT Integration]
        G[Hybrid Fusion<br/>Multi-Modal]
        H[Lite Engine<br/>Fast Analysis]
    end

    subgraph "Analyzers"
        I[Deep Learning<br/>Neural Networks]
        J[Multi-Language<br/>9+ Languages]
        K[Real-time<br/>Live Monitoring]
        L[Semantic<br/>Code Understanding]
    end

    A --> I
    B --> J
    C --> K
    D --> L
    E --> I
    F --> I
    G --> J
    H --> K

    style A fill:#ffcdd2
    style B fill:#f8bbd9
    style C fill:#e1bee7
    style D fill:#d1c4e9
    style E fill:#c5cae9
    style F fill:#bbdefb
    style G fill:#b3e5fc
    style H fill:#b2ebf2
    style I fill:#b2dfdb
    style J fill:#c8e6c9
    style K fill:#dcedc1
    style L fill:#f0f4c3
```

## Data Flow Architecture

```mermaid
flowchart TD
    START([Code Input]) --> DETECT{Language Detection}

    DETECT -->|Python| PY[Python Analyzer]
    DETECT -->|JavaScript/TS| JS[JS/TS Analyzer]
    DETECT -->|Go| GO[Go Analyzer]
    DETECT -->|Rust| RS[Rust Analyzer]
    DETECT -->|C/C++| CPP[C/C++ Analyzer]
    DETECT -->|Java| JAVA[Java Analyzer]
    DETECT -->|PHP| PHP[PHP Analyzer]

    PY --> EXTRACT[Feature Extraction]
    JS --> EXTRACT
    GO --> EXTRACT
    RS --> EXTRACT
    CPP --> EXTRACT
    JAVA --> EXTRACT
    PHP --> EXTRACT

    EXTRACT --> MATH[Mathematical Analysis]
    EXTRACT --> SEMANTIC[Semantic Analysis]
    EXTRACT --> PATTERN[Pattern Matching]

    MATH --> FUSION[Hybrid Fusion]
    SEMANTIC --> FUSION
    PATTERN --> FUSION

    FUSION --> CONFIDENCE[Confidence Scoring]
    CONFIDENCE --> EXPLAINABLE[Explainable Results]

    EXPLAINABLE --> OUTPUT([Vulnerability Report])

    style START fill:#4caf50
    style DETECT fill:#ff9800
    style EXTRACT fill:#2196f3
    style FUSION fill:#9c27b0
    style OUTPUT fill:#f44336
```

## Real-time Monitoring Architecture

```mermaid
sequenceDiagram
    participant FS as File System
    participant FM as File Monitor
    participant AQ as Analysis Queue
    participant AW as Analysis Workers
    participant WS as WebSocket Server
    participant CLIENT as Client Browser

    FS->>FM: File Change Event
    FM->>FM: Debounce & Filter
    FM->>AQ: Queue Analysis Task

    loop Analysis Workers
        AQ->>AW: Get Analysis Task
        AW->>AW: Run Vulnerability Analysis
        AW->>WS: Send Alert
    end

    WS->>CLIENT: Real-time Alert
    CLIENT->>CLIENT: Display Vulnerability

    Note over FM,AW: Multi-threaded Processing
    Note over WS,CLIENT: Live WebSocket Connection
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "Kubernetes Cluster"
        subgraph "Frontend"
            NGINX[NGINX Ingress]
            WEB[Web Interface]
        end

        subgraph "Application Layer"
            API1[VulnHunter API Pod 1]
            API2[VulnHunter API Pod 2]
            API3[VulnHunter API Pod 3]
            RT1[Real-time Monitor Pod]
        end

        subgraph "Storage"
            MODELS[Model Storage PVC]
            CONFIG[Config Maps]
            SECRETS[Secrets]
        end

        subgraph "Monitoring"
            PROM[Prometheus]
            GRAF[Grafana]
            LOGS[Log Aggregation]
        end
    end

    NGINX --> WEB
    NGINX --> API1
    NGINX --> API2
    NGINX --> API3

    API1 --> MODELS
    API2 --> MODELS
    API3 --> MODELS
    RT1 --> MODELS

    API1 --> CONFIG
    API2 --> CONFIG
    API3 --> CONFIG

    API1 --> SECRETS
    API2 --> SECRETS
    API3 --> SECRETS

    PROM --> API1
    PROM --> API2
    PROM --> API3
    PROM --> RT1

    GRAF --> PROM
    LOGS --> API1
    LOGS --> API2
    LOGS --> API3
    LOGS --> RT1

    style NGINX fill:#4caf50
    style WEB fill:#2196f3
    style API1 fill:#ff9800
    style API2 fill:#ff9800
    style API3 fill:#ff9800
    style RT1 fill:#9c27b0
```

## Security Architecture

```mermaid
graph TD
    subgraph "Security Layers"
        AUTH[Authentication]
        AUTHZ[Authorization]
        CRYPTO[Encryption]
        AUDIT[Audit Logging]
    end

    subgraph "Input Validation"
        SANITIZE[Input Sanitization]
        VALIDATE[Code Validation]
        LIMIT[Rate Limiting]
    end

    subgraph "Analysis Security"
        SANDBOX[Sandboxed Execution]
        TIMEOUT[Analysis Timeout]
        MEMORY[Memory Limits]
    end

    subgraph "Output Security"
        FILTER[Result Filtering]
        REDACT[Sensitive Data Redaction]
        SIGN[Digital Signatures]
    end

    AUTH --> SANITIZE
    AUTHZ --> VALIDATE
    CRYPTO --> LIMIT
    AUDIT --> SANDBOX

    SANITIZE --> SANDBOX
    VALIDATE --> TIMEOUT
    LIMIT --> MEMORY

    SANDBOX --> FILTER
    TIMEOUT --> REDACT
    MEMORY --> SIGN

    style AUTH fill:#f44336
    style AUTHZ fill:#e91e63
    style CRYPTO fill:#9c27b0
    style AUDIT fill:#673ab7
```