import pandas as pd
import matplotlib.pyplot as plt

def load_experiment_data(csv_file):
    df = pd.read_csv(csv_file)
    return df

def summarize_results(df):
    summary = {}
    for config in ['baseline', 'defense']:
        config_df = df[df['config'] == config]
        attacks = config_df[config_df['scenario'] == 'attack_stolen_key']
        summary[config] = {
            "n_trials": len(attacks),
            "accepted": sum(attacks['registry_response'] == "ACCEPTED"),
            "accept_rate": sum(attacks['registry_response'] == "ACCEPTED")/len(attacks) if len(attacks) else 0,
            "mean_detection_latency": attacks['detection_latency'].mean() if len(attacks) else None
        }
    return summary

def plot_acceptance_rates(summary):
    configs = list(summary.keys())
    rates = [summary[c]["accept_rate"] for c in configs]
    plt.bar(configs, rates, color=["orange","teal"])
    plt.ylabel("Malicious Acceptance Rate (Registry)")
    plt.title("Malicious Artifact Acceptance Rate by Environment")
    plt.show()

def plot_detection_latency(summary):
    configs = list(summary.keys())
    means = [summary[c]["mean_detection_latency"] for c in configs]
    plt.bar(configs, means, color=["blue", "green"])
    plt.ylabel("Mean Detection Latency (seconds)")
    plt.title("Detection Latency (Stolen Key Attack)")
    plt.show()

# Example usage:
# df = load_experiment_data('experiment_results_baseline.csv')
# summary = summarize_results(df)
# plot_acceptance_rates(summary)
# plot_detection_latency(summary)
