import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import os
import pickle
from pybloom_live import ScalableBloomFilter

# === File Paths ===
GRAPH_FILE = "user_ip_graph.pkl"
CSV_FILE = "cyber1_scored1.csv"
IMAGE_FILE = "user_ip_graph.png"
BLOOM_FILTER_FILE = "high_risk_users.bf"

# === Load or Create Graph ===
def load_graph():
    if os.path.exists(GRAPH_FILE):
        with open(GRAPH_FILE, "rb") as f:
            return pickle.load(f)
    return nx.Graph()

def save_graph(G):
    with open(GRAPH_FILE, "wb") as f:
        pickle.dump(G, f)

# === Update Graph from CSV with Edge Weight Accumulation ===
def update_graph_from_csv(G, csv_file):
    df = pd.read_csv(csv_file)
    df = df[['Username', 'Source IP', 'Failed Login Count', 'Risk_Score_IF']]

    # Total failed logins per user
    user_failed_counts = df.groupby('Username')['Failed Login Count'].sum().to_dict()

    # Latest score for each (user, ip)
    latest_scores = df.groupby(['Username', 'Source IP']).last().reset_index()

    for _, row in latest_scores.iterrows():
        user = row['Username']
        ip = row['Source IP']
        latest_risk_score = row['Risk_Score_IF']
        total_failed = user_failed_counts.get(user, 0)

        combined_score = total_failed * latest_risk_score

        G.add_node(user, type="user")
        G.add_node(ip, type="ip")

        # Update or create edge
        if G.has_edge(user, ip):
            G[user][ip]['weight'] += combined_score
        else:
            G.add_edge(user, ip, weight=combined_score)

    return G

# === Compute PageRank Scores ===
def compute_pagerank(G):
    scores = nx.pagerank(G, alpha=0.85, max_iter=100, weight='weight')
    for node, score in scores.items():
        G.nodes[node]['pagerank'] = score
    return G

# === Get Top N Users by PageRank ===
def get_top_users(G, top_n=10):
    return sorted(
        [(n, d["pagerank"]) for n, d in G.nodes(data=True) if d.get("type") == "user"],
        key=lambda x: x[1],
        reverse=True
    )[:top_n]

# === Draw and Save Graph as PNG ===
def draw_and_save_graph(G, image_path):
    pos = nx.spring_layout(G, seed=42)
    node_colors = ['skyblue' if G.nodes[n].get('type') == 'user' else 'lightgreen' for n in G.nodes()]
    node_sizes = [1000 * G.nodes[n].get('pagerank', 1) for n in G.nodes()]

    plt.figure(figsize=(12, 8))
    nx.draw(G, pos, with_labels=True, node_color=node_colors, node_size=node_sizes, edge_color='gray')
    plt.title("User-IP Graph with Combined Risk and PageRank")
    plt.savefig(image_path)
    plt.close()

# === Store High-Risk Users in Bloom Filter ===
def store_high_risk_users(G, threshold_pagerank=0.01, threshold_risk=5):
    bf = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH)

    for node, data in G.nodes(data=True):
        if data.get('type') == 'user':
            pagerank_score = data.get('pagerank', 0)
            connected_edges = G.edges(node, data=True)
            total_risk = sum([edata['weight'] for _, _, edata in connected_edges])

            if pagerank_score >= threshold_pagerank and total_risk >= threshold_risk:
                bf.add(node)

    with open(BLOOM_FILTER_FILE, "wb") as f:
        pickle.dump(bf, f)

    return bf

# === Check if a User is High-Risk via Bloom Filter ===
def is_high_risk_user(user):
    if not os.path.exists(BLOOM_FILTER_FILE):
        return False
    with open(BLOOM_FILTER_FILE, "rb") as f:
        bf = pickle.load(f)
    return user in bf

# === Main Execution Block ===
if __name__ == "__main__":
    G = nx.Graph()  # Start fresh (or load_graph() to persist)
    G = update_graph_from_csv(G, CSV_FILE)
    G = compute_pagerank(G)
    save_graph(G)
    draw_and_save_graph(G, IMAGE_FILE)

    # Build bloom filter for high-risk users
    bf = store_high_risk_users(G)

    # Display top users with risk status
    print("Top Suspicious Users by Combined Risk (PageRank):")
    for user, score in get_top_users(G):
        risk_status = "HIGH RISK" if is_high_risk_user(user) else "low risk"
        print(f"{user}: {score*100:.4f} - {risk_status}")
