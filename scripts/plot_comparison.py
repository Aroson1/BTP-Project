"""Optional scientific figure from a completed comparison (matplotlib required)."""
import csv
import json
from pathlib import Path
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from write_comparison_docs import LABELS


def plot(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    with (directory / "summary.csv").open() as f:
        rows = list(csv.DictReader(f))[::-1]
    y = list(range(len(rows)))
    colors = ["#15876c" if r["configuration"] in {"hybrid_validated_k3", "Progent_exact_plus_hybrid"}
              else "#487db3" if r["configuration"].startswith("Progent_")
              else "#b48243" if not r["configuration"].startswith("C") else "#718096" for r in rows]
    fig, axes = plt.subplots(1, 2, figsize=(14, 8.5), sharey=True)
    for ax, field, title in zip(axes, ("benign_success_pct", "attack_success_pct"),
                               ("Benign success (%) — higher is better", "Harmful effects (%) — lower is better")):
        values = [float(r[field]) for r in rows]
        ax.barh(y, values, color=colors, height=.68)
        for pos, value in zip(y, values):
            ax.text(value + 1, pos, f"{value:g}", va="center", fontsize=9)
        ax.set_xlim(0, 112)
        ax.set_xticks([0, 25, 50, 75, 100])
        ax.set_title(title, fontsize=11, pad=15)
        ax.grid(axis="x", alpha=.2)
        ax.set_axisbelow(True)
        for edge in ("top", "right", "left"):
            ax.spines[edge].set_visible(False)
    axes[0].set_yticks(y, [LABELS[r["configuration"]] for r in rows], fontsize=9)
    fig.suptitle("Policy generation and Progent: controlled execution results", fontsize=16, y=.975)
    context_count = len(manifest["tasks"])
    workflow_count = len({t["kind"] for t in manifest["tasks"]})
    caption = (f"{context_count} contexts · {workflow_count} workflow implementations · "
               f"{rows[0]['benign_total']} benign + {rows[0]['attack_total']} attacks per configuration · no model calls")
    fig.text(.5, .925, caption,
             ha="center", fontsize=10, color="#4a5568")
    fig.text(.5, .025, "Scripted operations with fixed tool calls; these are not live-agent or published Progent benchmark scores.",
             ha="center", fontsize=9, color="#4a5568")
    fig.subplots_adjust(left=.32, right=.97, top=.87, bottom=.09, wspace=.13)
    for extension in ("png", "svg"):
        fig.savefig(directory / ("comparison." + extension), dpi=180, facecolor="white")
    plt.close(fig)
    print("Saved comparison.png and comparison.svg")


if __name__ == "__main__":
    plot(sys.argv[1])
