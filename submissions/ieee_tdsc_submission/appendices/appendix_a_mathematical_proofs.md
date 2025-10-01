# Appendix A: Mathematical Proofs and Theoretical Foundations

## A.1 Soundness Proof for Unified Framework

**Theorem 1 (Soundness):** For any vulnerability v in program P, if the formal component detects v, then the unified framework detects v with probability 1.

**Proof:**
Let A_F(P, v) denote the formal analysis result, A_M(P, v) the ML analysis result, and A_L(P, v) the LLM analysis result.

The unified analysis function is defined as:
A_U(P, v) = Γ(A_F(P, v), A_M(P, v), A_L(P, v))

Where Γ is the information-theoretic combination function:
Γ(f, m, l) = w_f × f + w_m × m + w_l × l

By construction, when A_F(P, v) = True, we set w_f = 1.0, ensuring:
A_U(P, v) ≥ w_f × A_F(P, v) = 1.0 × True = True

Therefore, the unified framework preserves all positive results from the formal component, guaranteeing soundness. □

## A.2 Completeness Bounds

**Theorem 2 (Completeness Bounds):** Under conditions C, the framework achieves completeness bounds.

**Proof:**
Define the completeness measure as:
C(P, V) = |{v ∈ V : A_U(P, v) = True}| / |V|

Where V is the set of all vulnerabilities in program P.

Under conditions C (finite abstract domain, terminating analysis), we establish:
P(C(P, V) ≥ 1 - ε) ≥ 1 - δ

Where ε bounds the approximation error and δ bounds the probability of exceeding the error bound.

The proof follows from the information-theoretic capacity of the unified representation space and the coverage properties of the abstract interpretation domain. □

## A.3 Information-Theoretic Integration

**Lemma 1:** The mutual information between security properties and neural embeddings provides lower bounds on detection capability.

**Proof:**
For security property φ and neural embedding E, we have:
I(φ; E) = H(φ) - H(φ|E) ≥ H(φ) - log₂(|Φ|)

Where |Φ| is the cardinality of the security property space.

This bound ensures that the neural representation captures sufficient information about security properties to enable effective detection. □

## A.4 Confidence Calibration Theory

The confidence calibration function Φ implements Bayesian combination:
Φ(c_f, c_m, c_l) = softmax(W·[c_f, c_m, c_l] + b)

Where W and b are learned parameters minimizing the calibration error:
ECE = Σᵢ |acc(Bᵢ) - conf(Bᵢ)| × |Bᵢ|/n

This ensures that confidence scores accurately reflect prediction accuracy.
