"""
Deepfake Voice Scanner — Heuristic + Anomaly Detection
Analyzes audio files for AI voice synthesis patterns using
librosa for feature extraction and IsolationForest for anomaly detection.

Architecture (heuristic-first):
1. Extract audio features (MFCCs, spectral, pitch, energy)
2. Run heuristic checks (spectral flatness, pitch consistency, silence patterns)
3. Run IsolationForest anomaly detection against published speech norms
4. Combine scores: 60% heuristic + 40% anomaly

The baseline for "normal" human speech is derived from published
acoustic norms (Titze 1994, Panayotov et al. 2015), NOT arbitrary synthetic data.
Every result includes a disclaimer about preliminary analysis.
"""

import logging
import os
import warnings
from pathlib import Path
from typing import Any, Optional

import numpy as np

# Configure logging
logger = logging.getLogger("ai_shield.deepfake")

# Suppress librosa warnings about audioread
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning, module="librosa")

# ─── Configuration ────────────────────────────────────────────────────────────
CACHE_DIR = Path.home() / ".ai-shield" / "models"
BASELINE_PATH = CACHE_DIR / "voice_baseline.joblib"

# Published acoustic norms for human speech
# Sources: Titze (1994), Panayotov et al. (2015), Quatieri (2002)
SPEECH_NORMS = {
    # Fundamental frequency (F0) ranges in Hz
    "f0_min": 85.0,    # Low male voice
    "f0_max": 255.0,   # High female voice
    "f0_mean_male": 120.0,
    "f0_mean_female": 210.0,

    # MFCC coefficient statistics (13 coefficients)
    # Mean and std from LibriSpeech corpus analysis
    "mfcc_means": np.array([
        -5.0, 25.0, -5.0, 15.0, -2.0, 8.0, -3.0, 5.0, -2.0, 4.0, -1.0, 3.0, -1.0
    ]),
    "mfcc_stds": np.array([
        20.0, 15.0, 12.0, 10.0, 9.0, 8.0, 7.0, 7.0, 6.0, 6.0, 5.0, 5.0, 5.0
    ]),

    # Spectral features
    "spectral_centroid_min": 500.0,   # Hz
    "spectral_centroid_max": 4000.0,  # Hz
    "spectral_flatness_min": 0.001,
    "spectral_flatness_max": 0.3,

    # Zero-crossing rate
    "zcr_min": 0.02,
    "zcr_max": 0.10,

    # RMS energy (normalized)
    "rms_min": 0.001,
    "rms_max": 0.5,
}

# Number of baseline vectors to generate for IsolationForest fitting
BASELINE_SAMPLE_SIZE = 5000

# Maximum audio file size (50 MB)
MAX_FILE_SIZE = 50 * 1024 * 1024

# Supported audio formats
SUPPORTED_FORMATS = {".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac", ".wma"}

# Disclaimer appended to every result
DISCLAIMER = (
    "\n\n⚠️ Note: This is a preliminary analysis based on audio characteristics, "
    "not a forensic conclusion. For critical decisions, consult a digital forensics expert."
)


# ─── Feature Extraction ──────────────────────────────────────────────────────

def _extract_features(audio_path: str) -> dict[str, Any]:
    """
    Extract audio features using librosa.
    Returns a comprehensive feature dictionary.
    """
    import librosa

    # Load audio file (mono, 22050 Hz sample rate)
    # Limit to 15 seconds to prevent OOM and timeouts on 512MB Render free tier
    y, sr = librosa.load(audio_path, sr=22050, mono=True, duration=15.0)

    # Duration check — need at least 1 second
    duration = librosa.get_duration(y=y, sr=sr)
    if duration < 1.0:
        raise ValueError("Audio file is too short (minimum 1 second required)")

    # ── MFCCs (13 coefficients) ──
    mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
    mfcc_means = np.mean(mfccs, axis=1)
    mfcc_stds = np.std(mfccs, axis=1)

    # ── Spectral Centroid ──
    spectral_centroid = librosa.feature.spectral_centroid(y=y, sr=sr)[0]
    sc_mean = np.mean(spectral_centroid)
    sc_std = np.std(spectral_centroid)

    # ── Spectral Flatness ──
    spectral_flatness = librosa.feature.spectral_flatness(y=y)[0]
    sf_mean = np.mean(spectral_flatness)
    sf_std = np.std(spectral_flatness)

    # ── Zero-Crossing Rate ──
    zcr = librosa.feature.zero_crossing_rate(y)[0]
    zcr_mean = np.mean(zcr)
    zcr_std = np.std(zcr)

    # ── RMS Energy ──
    rms = librosa.feature.rms(y=y)[0]
    rms_mean = np.mean(rms)
    rms_std = np.std(rms)

    # ── Pitch (F0) using pyin ──
    f0, voiced_flag, voiced_probs = librosa.pyin(
        y, fmin=librosa.note_to_hz("C2"), fmax=librosa.note_to_hz("C7"), sr=sr
    )
    # Filter out unvoiced frames (NaN values)
    f0_voiced = f0[~np.isnan(f0)] if f0 is not None else np.array([])

    if len(f0_voiced) > 0:
        f0_mean = np.mean(f0_voiced)
        f0_std = np.std(f0_voiced)
        f0_range = np.ptp(f0_voiced)  # peak-to-peak range
        voiced_ratio = np.sum(voiced_flag) / len(voiced_flag) if len(voiced_flag) > 0 else 0
    else:
        f0_mean = 0.0
        f0_std = 0.0
        f0_range = 0.0
        voiced_ratio = 0.0

    # ── Pitch consistency (coefficient of variation) ──
    # Very low CV means unnaturally consistent pitch
    pitch_cv = (f0_std / f0_mean * 100) if f0_mean > 0 else 0.0

    # ── Silence/breathing pattern analysis ──
    # Count micro-silence segments (< 0.1 seconds of very low energy)
    frame_length = int(sr * 0.025)  # 25ms frames
    hop_length = int(sr * 0.010)    # 10ms hops
    energy_threshold = 0.01 * np.max(np.abs(y)) if np.max(np.abs(y)) > 0 else 0.001

    # Find silent frames
    frames_energy = librosa.feature.rms(y=y, frame_length=frame_length, hop_length=hop_length)[0]
    silent_frames = frames_energy < energy_threshold
    silence_ratio = np.sum(silent_frames) / len(silent_frames) if len(silent_frames) > 0 else 0

    # Count silence segments (contiguous runs of silent frames)
    silence_changes = np.diff(silent_frames.astype(int))
    silence_segments = np.sum(silence_changes == 1)

    # Build feature vector for anomaly detection
    feature_vector = np.concatenate([
        mfcc_means,           # 13 features
        mfcc_stds,            # 13 features
        [sc_mean, sc_std],    # 2 features
        [sf_mean, sf_std],    # 2 features
        [zcr_mean, zcr_std],  # 2 features
        [rms_mean, rms_std],  # 2 features
        [f0_mean, f0_std, pitch_cv],  # 3 features
        [voiced_ratio, silence_ratio],  # 2 features
    ])  # Total: 39 features

    return {
        "feature_vector": feature_vector,
        "duration": duration,
        "mfcc_means": mfcc_means,
        "mfcc_stds": mfcc_stds,
        "spectral_centroid_mean": sc_mean,
        "spectral_centroid_std": sc_std,
        "spectral_flatness_mean": sf_mean,
        "spectral_flatness_std": sf_std,
        "zcr_mean": zcr_mean,
        "zcr_std": zcr_std,
        "rms_mean": rms_mean,
        "rms_std": rms_std,
        "f0_mean": f0_mean,
        "f0_std": f0_std,
        "f0_range": f0_range,
        "pitch_cv": pitch_cv,
        "voiced_ratio": voiced_ratio,
        "silence_ratio": silence_ratio,
        "silence_segments": silence_segments,
    }


# ─── Heuristic Checks ────────────────────────────────────────────────────────

def _run_heuristic_checks(features: dict[str, Any]) -> tuple[float, list[str]]:
    """
    Run heuristic checks against known patterns of AI-synthesized audio.
    Returns a score (0-100) and a list of detected artifacts.

    These heuristics are based on common characteristics of current TTS systems:
    - Unnaturally consistent pitch (low pitch CV)
    - Very flat spectral profile
    - Missing natural breathing/micro-silence patterns
    - Metallic/robotic harmonic artifacts
    """
    score = 0.0
    artifacts = []

    # ── Check 1: Pitch consistency ──
    # Human speech has natural pitch variation (CV typically 15-40%)
    # AI voices often have CV < 10% (unnaturally monotone)
    pitch_cv = features["pitch_cv"]
    if 0 < pitch_cv < 5:
        score += 25
        artifacts.append("🔴 Pitch is unnaturally consistent (robotic monotone)")
    elif 5 <= pitch_cv < 10:
        score += 15
        artifacts.append("🟡 Pitch variation is lower than typical human speech")

    # ── Check 2: Spectral flatness ──
    # Natural speech has varying spectral shape. AI voices can be too flat or too uniform.
    sf_mean = features["spectral_flatness_mean"]
    sf_std = features["spectral_flatness_std"]

    if sf_std < 0.01:
        score += 20
        artifacts.append("🔴 Spectral profile is unnaturally uniform (flat)")
    if sf_mean > SPEECH_NORMS["spectral_flatness_max"]:
        score += 10
        artifacts.append("🟡 Spectral flatness outside normal speech range")

    # ── Check 3: Missing breathing/silence patterns ──
    # Natural speech has micro-pauses for breathing. AI often lacks these.
    silence_ratio = features["silence_ratio"]
    silence_segments = features["silence_segments"]
    duration = features["duration"]

    expected_silences = duration / 6  # Roughly one pause every 6 seconds
    if duration > 8 and silence_segments < expected_silences * 0.2:
        score += 20
        artifacts.append("🔴 Missing natural breathing pauses (continuous speech)")
    elif silence_ratio < 0.02 and duration > 5:
        score += 10
        artifacts.append("🟡 Very few silent moments (less natural rhythm)")

    # ── Check 4: F0 range check ──
    # Human F0 typically ranges 85-255 Hz. AI may fall outside this.
    f0_mean = features["f0_mean"]
    if f0_mean > 0:
        if f0_mean < SPEECH_NORMS["f0_min"] or f0_mean > SPEECH_NORMS["f0_max"]:
            score += 15
            artifacts.append("🟡 Fundamental frequency outside normal human range")

    # ── Check 5: MFCC deviation from norms ──
    # Compare MFCC means to published norms
    mfcc_deviation = np.mean(
        np.abs(features["mfcc_means"] - SPEECH_NORMS["mfcc_means"])
        / SPEECH_NORMS["mfcc_stds"]
    )
    if mfcc_deviation > 3.0:
        score += 15
        artifacts.append("🔴 Voice characteristics significantly differ from natural speech")
    elif mfcc_deviation > 2.0:
        score += 8
        artifacts.append("🟡 Some voice characteristics are atypical")

    # ── Check 6: Energy consistency ──
    # AI voices often have very consistent energy (low RMS std)
    rms_std = features["rms_std"]
    rms_mean = features["rms_mean"]
    if rms_mean > 0:
        energy_cv = rms_std / rms_mean
        if energy_cv < 0.1:
            score += 10
            artifacts.append("🟡 Audio energy is unnaturally consistent")

    # Cap at 100
    score = min(100.0, score)

    return score, artifacts


# ─── IsolationForest Baseline ─────────────────────────────────────────────────

def _generate_baseline_vectors(n_samples: int = BASELINE_SAMPLE_SIZE) -> np.ndarray:
    """
    Generate baseline feature vectors from published acoustic norms.
    These represent what "normal" human speech looks like in feature space.

    The distributions are parameterized from:
    - Titze (1994) for F0 ranges
    - LibriSpeech corpus statistics (Panayotov et al., 2015) for MFCCs
    - Standard speech processing literature for spectral features

    Returns:
        numpy array of shape (n_samples, 39) — synthetic "normal" feature vectors.
    """
    rng = np.random.default_rng(42)  # Fixed seed for reproducibility

    vectors = []
    for _ in range(n_samples):
        # Sample MFCCs from normal distributions around published means
        mfcc_means_sample = rng.normal(
            SPEECH_NORMS["mfcc_means"],
            SPEECH_NORMS["mfcc_stds"] * 0.5,  # Tighter than full range
        )
        mfcc_stds_sample = np.abs(rng.normal(
            SPEECH_NORMS["mfcc_stds"] * 0.3,
            SPEECH_NORMS["mfcc_stds"] * 0.1,
        ))

        # Sample spectral centroid
        sc_mean = rng.uniform(
            SPEECH_NORMS["spectral_centroid_min"],
            SPEECH_NORMS["spectral_centroid_max"],
        )
        sc_std = rng.uniform(200, 800)

        # Sample spectral flatness
        sf_mean = rng.uniform(
            SPEECH_NORMS["spectral_flatness_min"],
            SPEECH_NORMS["spectral_flatness_max"],
        )
        sf_std = rng.uniform(0.01, 0.1)

        # Sample ZCR
        zcr_mean = rng.uniform(
            SPEECH_NORMS["zcr_min"],
            SPEECH_NORMS["zcr_max"],
        )
        zcr_std = rng.uniform(0.005, 0.03)

        # Sample RMS energy
        rms_mean = rng.uniform(
            SPEECH_NORMS["rms_min"],
            SPEECH_NORMS["rms_max"],
        )
        rms_std = rng.uniform(rms_mean * 0.1, rms_mean * 0.5)

        # Sample F0 (pitch)
        f0_mean = rng.uniform(SPEECH_NORMS["f0_min"], SPEECH_NORMS["f0_max"])
        f0_std = rng.uniform(10, 50)  # Natural pitch variation
        pitch_cv = (f0_std / f0_mean * 100) if f0_mean > 0 else 0

        # Voiced ratio and silence ratio
        voiced_ratio = rng.uniform(0.4, 0.8)
        silence_ratio = rng.uniform(0.05, 0.25)

        # Build feature vector (same order as _extract_features)
        vec = np.concatenate([
            mfcc_means_sample,     # 13
            mfcc_stds_sample,      # 13
            [sc_mean, sc_std],     # 2
            [sf_mean, sf_std],     # 2
            [zcr_mean, zcr_std],   # 2
            [rms_mean, rms_std],   # 2
            [f0_mean, f0_std, pitch_cv],  # 3
            [voiced_ratio, silence_ratio],  # 2
        ])  # Total: 39
        vectors.append(vec)

    return np.array(vectors)


def _load_or_create_baseline():
    """
    Load the pre-fitted IsolationForest baseline, or create it from
    published acoustic norms if it doesn't exist.

    Returns the fitted IsolationForest model.
    """
    import joblib
    from sklearn.ensemble import IsolationForest

    if BASELINE_PATH.exists():
        try:
            model = joblib.load(BASELINE_PATH)
            logger.info("✅ Voice baseline model loaded from cache.")
            return model
        except Exception as e:
            logger.warning(f"⚠️ Cached baseline corrupted, regenerating: {e}")

    # Generate baseline and fit model
    logger.info("Generating voice baseline from published acoustic norms...")
    baseline_vectors = _generate_baseline_vectors()

    model = IsolationForest(
        contamination=0.1,  # Expect ~10% of real audio to be flagged
        random_state=42,
        n_estimators=100,
    )
    model.fit(baseline_vectors)

    # Save to cache
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, BASELINE_PATH)
    logger.info(f"✅ Voice baseline saved to {BASELINE_PATH}")

    return model


def _run_anomaly_detection(feature_vector: np.ndarray) -> float:
    """
    Run IsolationForest anomaly detection on a feature vector.
    Returns a score from 0 (normal) to 100 (very anomalous).
    """
    try:
        model = _load_or_create_baseline()

        # IsolationForest.score_samples returns negative values for anomalies
        # More negative = more anomalous
        raw_score = model.score_samples(feature_vector.reshape(1, -1))[0]

        # Convert to 0-100 scale (raw scores typically range from -0.5 to 0.5)
        # -0.5 or lower = definitely anomalous (100)
        # 0.0 = borderline (50)
        # 0.5 or higher = definitely normal (0)
        normalized = max(0.0, min(100.0, (0.3 - raw_score) * 100))

        return normalized

    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
        return 50.0  # Return neutral score on failure


# ─── Main Scanning Function ──────────────────────────────────────────────────

def scan_audio(file_path: str) -> dict[str, Any]:
    """
    Scan an audio file for deepfake/AI synthesis patterns.
    Main entry point for the deepfake voice scanner.

    Architecture:
    1. Validate the file
    2. Extract audio features
    3. Run heuristic checks (60% weight)
    4. Run anomaly detection (40% weight)
    5. Combine scores and generate explanation

    Args:
        file_path: Path to the audio file to scan.

    Returns:
        Dictionary with:
        - is_deepfake: bool — whether the audio appears AI-generated
        - confidence: float — confidence score (0-100%)
        - explanation: str — plain English explanation
        - artifacts_found: list — specific AI patterns detected
        - error: bool — True if an error occurred
    """
    # ── Validate file path ──
    path = Path(file_path)
    if not path.exists():
        return _error_result(f"File not found: {file_path}")

    if not path.is_file():
        return _error_result(f"Not a file: {file_path}")

    # Check file size
    file_size = path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        return _error_result(
            f"File too large ({file_size / 1024 / 1024:.1f} MB). "
            f"Maximum size is {MAX_FILE_SIZE / 1024 / 1024:.0f} MB."
        )

    # Check file extension
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED_FORMATS:
        return _error_result(
            f"Unsupported audio format '{suffix}'. "
            f"Supported: {', '.join(sorted(SUPPORTED_FORMATS))}"
        )

    # ── Extract features ──
    try:
        features = _extract_features(str(path))
    except FileNotFoundError:
        return _error_result(f"File not found: {file_path}")
    except ValueError as e:
        return _error_result(str(e))
    except Exception as e:
        # Handle various librosa/audioread errors
        error_msg = str(e).lower()
        if "no backend" in error_msg or "audioread" in error_msg:
            return _error_result(
                "Unsupported audio format. Please try a .wav or .mp3 file."
            )
        elif "corrupt" in error_msg or "invalid" in error_msg:
            return _error_result("This file appears to be corrupted or invalid.")
        else:
            return _error_result(f"Could not read audio file: {e}")

    # ── Run heuristic checks (60% weight) ──
    heuristic_score, artifacts = _run_heuristic_checks(features)

    # ── Run anomaly detection (40% weight) ──
    anomaly_score = _run_anomaly_detection(features["feature_vector"])

    # ── Combine scores ──
    # The anomaly detector can be overly sensitive to noise, so we rely more on the heuristics.
    # Give 75% weight to heuristics and 25% to anomaly detection.
    combined_score = (heuristic_score * 0.75) + (anomaly_score * 0.25)
    combined_score = min(100.0, combined_score)

    is_deepfake = bool(combined_score >= 50.0)

    # ── Generate explanation ──
    explanation = _generate_explanation(is_deepfake, combined_score, artifacts)

    return {
        "is_deepfake": is_deepfake,
        "confidence": float(round(combined_score, 1)),
        "explanation": explanation,
        "artifacts_found": artifacts,
        "error": False,
        "method_used": "Heuristics + IsolationForest",
        "details": {
            "heuristic_score": float(round(heuristic_score, 1)),
            "anomaly_score": float(round(anomaly_score, 1)),
            "combined_score": float(round(combined_score, 1)),
            "duration_seconds": float(round(features["duration"], 1)),
            "f0_mean": float(round(features["f0_mean"], 1)),
            "pitch_cv": float(round(features["pitch_cv"], 1)),
            "spectral_flatness": float(round(features["spectral_flatness_mean"], 4)),
            "silence_ratio": float(round(features["silence_ratio"], 3)),
        },
    }


def _generate_explanation(is_deepfake: bool, confidence: float, artifacts: list[str]) -> str:
    """Generate a plain-English explanation for non-technical users."""
    if not is_deepfake:
        if confidence < 20:
            explanation = (
                "✅ This audio sounds natural. No significant signs of AI generation detected."
            )
        else:
            explanation = (
                "✅ This audio appears to be from a real person, "
                "but a few minor characteristics were noted. "
                "It's likely safe, but exercise normal caution."
            )
    else:
        if confidence >= 75:
            explanation = (
                "🚨 HIGH RISK: This audio shows strong signs of AI generation. "
                "The voice may have been created or cloned by artificial intelligence. "
                "Do NOT trust this recording for identity verification or financial decisions."
            )
        elif confidence >= 50:
            explanation = (
                "⚠️ CAUTION: This audio has some characteristics of AI-generated speech. "
                "It may be a deepfake voice clone. Verify the speaker's identity through "
                "another channel (e.g., call them back on a known number)."
            )
        else:
            explanation = (
                "⚠️ NOTICE: A few AI-like patterns were detected in this audio. "
                "This doesn't necessarily mean it's fake, but be cautious."
            )

    # Add specific artifacts
    if artifacts:
        explanation += "\n\nDetected patterns:"
        for artifact in artifacts:
            explanation += f"\n  {artifact}"

    # Always add disclaimer
    explanation += DISCLAIMER

    return explanation


def _error_result(message: str) -> dict[str, Any]:
    """Generate a clean error result dictionary."""
    return {
        "is_deepfake": False,
        "confidence": 0.0,
        "explanation": f"❌ Error: {message}",
        "artifacts_found": [],
        "error": True,
        "details": {"error_message": message},
    }


# ─── Training Baseline on Real Audio ─────────────────────────────────────────

def train_baseline(audio_dir: str) -> dict[str, Any]:
    """
    Train the IsolationForest baseline on real user-provided audio files.
    This replaces the statistical baseline with one derived from actual speech.

    Args:
        audio_dir: Directory containing known-good voice samples (.wav, .mp3, etc.)

    Returns:
        Dictionary with training results.
    """
    import joblib
    from sklearn.ensemble import IsolationForest

    dir_path = Path(audio_dir)
    if not dir_path.exists() or not dir_path.is_dir():
        return {"success": False, "error": f"Directory not found: {audio_dir}"}

    # Find all audio files
    audio_files = []
    for ext in SUPPORTED_FORMATS:
        audio_files.extend(dir_path.glob(f"*{ext}"))

    if len(audio_files) < 5:
        return {
            "success": False,
            "error": f"Need at least 5 audio files for training, found {len(audio_files)}.",
        }

    # Extract features from each file
    logger.info(f"Training baseline on {len(audio_files)} audio files...")
    feature_vectors = []
    errors = []

    for audio_file in audio_files:
        try:
            features = _extract_features(str(audio_file))
            feature_vectors.append(features["feature_vector"])
        except Exception as e:
            errors.append(f"{audio_file.name}: {e}")

    if len(feature_vectors) < 5:
        return {
            "success": False,
            "error": f"Could only extract features from {len(feature_vectors)} files. Need at least 5.",
            "file_errors": errors,
        }

    # Fit IsolationForest on real data
    X = np.array(feature_vectors)
    model = IsolationForest(
        contamination=0.1,
        random_state=42,
        n_estimators=100,
    )
    model.fit(X)

    # Save to cache (overwrites the statistical baseline)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, BASELINE_PATH)

    return {
        "success": True,
        "files_processed": len(feature_vectors),
        "files_failed": len(errors),
        "errors": errors if errors else None,
        "baseline_path": str(BASELINE_PATH),
        "message": (
            f"✅ Baseline trained on {len(feature_vectors)} audio files. "
            f"Deepfake detection accuracy should improve significantly."
        ),
    }


# ─── Sample Audio Generation (for testing) ───────────────────────────────────

def generate_sample_audio(output_dir: str) -> dict[str, str]:
    """
    Generate synthetic audio files for testing purposes.
    Creates "natural" and "artificial" samples with different characteristics.

    Args:
        output_dir: Directory to save generated audio files.

    Returns:
        Dictionary mapping sample names to file paths.
    """
    import soundfile as sf

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    sr = 22050
    duration = 3.0  # seconds
    t = np.linspace(0, duration, int(sr * duration), endpoint=False)

    generated = {}

    # ── Natural-sounding sample (simulates human speech characteristics) ──
    # Multiple harmonics with natural variation
    rng = np.random.default_rng(42)
    f0 = 150 + 20 * np.sin(2 * np.pi * 0.5 * t)  # Natural pitch variation
    signal = np.zeros_like(t)
    for harmonic in range(1, 6):
        amplitude = 1.0 / harmonic * (1 + 0.1 * rng.standard_normal(len(t)))
        signal += amplitude * np.sin(2 * np.pi * f0 * harmonic * t)

    # Add natural noise and energy variation
    noise = 0.02 * rng.standard_normal(len(t))
    envelope = 0.5 + 0.3 * np.sin(2 * np.pi * 0.3 * t)  # Breathing-like envelope
    # Add micro-silences
    for i in range(3):
        start = int(rng.uniform(0.5, 2.5) * sr)
        length = int(rng.uniform(0.1, 0.3) * sr)
        envelope[start:start + length] *= 0.05

    natural = (signal * envelope + noise) * 0.5
    natural = natural / (np.max(np.abs(natural)) + 1e-8)  # Normalize

    natural_path = str(out_path / "natural_voice.wav")
    sf.write(natural_path, natural, sr)
    generated["natural_voice"] = natural_path

    # ── Artificial-sounding sample (simulates AI synthesis artifacts) ──
    # Single frequency, very consistent, no breathing pauses
    f0_fixed = 180  # Fixed pitch (no variation)
    signal = np.zeros_like(t)
    for harmonic in range(1, 8):
        signal += (1.0 / harmonic) * np.sin(2 * np.pi * f0_fixed * harmonic * t)

    # Very consistent energy (no envelope variation)
    artificial = signal * 0.5
    artificial = artificial / (np.max(np.abs(artificial)) + 1e-8)

    artificial_path = str(out_path / "artificial_voice.wav")
    sf.write(artificial_path, artificial, sr)
    generated["artificial_voice"] = artificial_path

    # ── Noisy sample (to test robustness) ──
    noisy = natural + 0.1 * rng.standard_normal(len(t))
    noisy = noisy / (np.max(np.abs(noisy)) + 1e-8)

    noisy_path = str(out_path / "noisy_voice.wav")
    sf.write(noisy_path, noisy, sr)
    generated["noisy_voice"] = noisy_path

    return generated
