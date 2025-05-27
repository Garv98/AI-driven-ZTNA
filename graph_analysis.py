import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import os
import pickle
import csv 

def load_graph(graph_file="user_ip_graph.pkl"):
    if os.path.exists(graph_file):
        with open(graph_file, "rb") as f:
            return pickle.load(f)
    return nx.Graph()

def save_graph(G, graph_file="user_ip_graph.pkl"):
    with open(graph_file, "wb") as f:
        pickle.dump(G, f)

def export_pagerank_csv(G, out_csv="pagerank_scores.csv"):
    with open(out_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Node", "Type", "PageRank"])
        for n, d in G.nodes(data=True):
            writer.writerow([n, d.get("type", "unknown"), d.get("pagerank", 0)])

def update_graph_from_csv(G, csv_file):
    df = pd.read_csv(csv_file)
    df = df[['Username', 'Source IP', 'Failed Login Count', 'Risk Score']]

    user_failed_counts = df.groupby('Username')['Failed Login Count'].sum().to_dict()
    latest_scores = df.groupby(['Username', 'Source IP']).last().reset_index()

    for _, row in latest_scores.iterrows():
        user = row['Username']
        ip = row['Source IP']
        latest_risk_score = row['Risk Score']
        total_failed = user_failed_counts.get(user, 0)

        combined_score = total_failed * latest_risk_score

        G.add_node(user, type="user")
        G.add_node(ip, type="ip")
        G.add_edge(user, ip, weight=combined_score)

    return G

def compute_pagerank(G):
    scores = nx.pagerank(G, alpha=0.85, max_iter=100, weight='weight')
    for node, score in scores.items():
        G.nodes[node]['pagerank'] = score
    return G

def get_top_users(G, top_n=10):
    return sorted(
        [(n, d.get("pagerank", 0)) for n, d in G.nodes(data=True) if d.get("type") == "user"],
        key=lambda x: x[1],
        reverse=True
    )[:top_n]

def draw_and_save_graph(G, image_path="static/user_ip_graph.png"):
    pos = nx.spring_layout(G, seed=42)
    node_colors = ['skyblue' if G.nodes[n].get('type') == 'user' else 'lightgreen' for n in G.nodes()]
    node_sizes = [1000 * G.nodes[n].get('pagerank', 1) for n in G.nodes()]

    plt.figure(figsize=(12, 8))
    nx.draw(G, pos, with_labels=True, node_color=node_colors, node_size=node_sizes, edge_color='gray')
    plt.title("User-IP Graph with Combined Risk and PageRank")
    plt.savefig(image_path)
    plt.close()

def run_graph_analysis(csv_file="cyber1_scored.csv", image_path="static/user_ip_graph.png"):
    G = nx.Graph()
    G = update_graph_from_csv(G, csv_file)
    G = compute_pagerank(G)
    save_graph(G)
    draw_and_save_graph(G, image_path)
    export_pagerank_csv(G)  # ✅ Export PageRank scores
    return get_top_users(G)