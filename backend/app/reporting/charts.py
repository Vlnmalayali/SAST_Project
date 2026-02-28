"""Chart generation for PDF reports using matplotlib."""

import io
import logging

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#CA8A04",
    "low": "#16A34A",
    "info": "#6B7280",
}


def generate_severity_pie_chart(severity_counts: dict) -> bytes:
    """Generate a pie chart of vulnerability severity distribution."""
    labels = []
    sizes = []
    colors = []

    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            labels.append(f"{sev.title()} ({count})")
            sizes.append(count)
            colors.append(SEVERITY_COLORS[sev])

    if not sizes:
        return _empty_chart("No Vulnerabilities Found")

    fig, ax = plt.subplots(figsize=(6, 4))
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct="%1.0f%%",
        startangle=90,
        textprops={"fontsize": 9},
    )
    ax.set_title("Vulnerability Distribution by Severity", fontsize=12, fontweight="bold")
    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def generate_type_bar_chart(type_counts: dict) -> bytes:
    """Generate a bar chart of vulnerability types."""
    if not type_counts:
        return _empty_chart("No Vulnerabilities Found")

    types = list(type_counts.keys())
    counts = list(type_counts.values())
    display_labels = [t.replace("_", " ").title() for t in types]

    fig, ax = plt.subplots(figsize=(8, 4))
    bars = ax.barh(display_labels, counts, color="#3B82F6", edgecolor="#1E40AF")
    ax.set_xlabel("Count")
    ax.set_title("Vulnerabilities by Type", fontsize=12, fontweight="bold")

    for bar, count in zip(bars, counts):
        ax.text(
            bar.get_width() + 0.3,
            bar.get_y() + bar.get_height() / 2,
            str(count),
            va="center",
            fontsize=9,
        )

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def generate_risk_gauge(score: float) -> bytes:
    """Generate a risk score gauge visualization."""
    fig, ax = plt.subplots(figsize=(4, 3))

    if score >= 8:
        color = "#DC2626"
        label = "Critical"
    elif score >= 6:
        color = "#EA580C"
        label = "High"
    elif score >= 4:
        color = "#CA8A04"
        label = "Medium"
    elif score >= 2:
        color = "#16A34A"
        label = "Low"
    else:
        color = "#22C55E"
        label = "Minimal"

    ax.barh([0], [score], color=color, height=0.5, edgecolor="black")
    ax.barh([0], [10 - score], left=[score], color="#E5E7EB", height=0.5, edgecolor="black")
    ax.set_xlim(0, 10)
    ax.set_yticks([])
    ax.set_xlabel("Risk Score")
    ax.set_title(f"Risk Score: {score}/10.0 — {label}", fontsize=12, fontweight="bold", color=color)

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def _empty_chart(message: str) -> bytes:
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.text(0.5, 0.5, message, ha="center", va="center", fontsize=14, color="#6B7280")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf.read()
