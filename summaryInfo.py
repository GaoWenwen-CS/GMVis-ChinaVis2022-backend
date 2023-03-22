import networkx as nx

def summary_data(graph):
    connectivity = nx.node_connectivity(graph)
    nodesnum = graph.number_of_nodes()
    edgesnum = graph.number_of_edges()
    result = {"connectivity":connectivity,"nodesnum":nodesnum,"edgesnum":edgesnum}
    return result