from subGraphMining import path_node_mining,node_mining
from subGraphStatistic import subgraph_node_statistics,subgraph_edge_statistics
from nodeInfo import node_info_statistic_type,node_info_statistic_edge_types,node_info_statistic_neighbors,node_info_statistic_weight
from edgeInfo import edge_info_statistic_type,edge_info_statistic_weight
from chordInfo import chord_chart_info
from summaryInfo import summary_data


def subg_mining(oriG,clue,edge_percent,max_count):
    path_nodes = path_node_mining(oriG,clue)
    jump1,jump2,jump3 = node_mining(oriG,clue,edge_percent)

    l = list(set(jump1+jump2+jump3+clue+path_nodes))

    if len(l)>max_count:
        jump1,jump2,jump3 = node_mining(oriG,clue,edge_percent,2)

    l = list(set(jump1+jump2+jump3+clue+path_nodes))

    subG = oriG.subgraph(list(l))
    print(len(l))

    nodes = subgraph_node_statistics(subG)
    edges = subgraph_edge_statistics(subG)

    node_types = node_info_statistic_type(nodes)
    node_weights = node_info_statistic_weight(nodes)
    node_edge_types = node_info_statistic_edge_types(nodes)
    node_neighbors = node_info_statistic_neighbors(nodes)
    nodes_info = {"types": node_types, "weights": node_weights, "edge_types": node_edge_types,
                  "neighbors": node_neighbors}

    edge_types = edge_info_statistic_type(edges)
    edge_weights = edge_info_statistic_weight(edges)
    edges_info = {"types": edge_types, "weights": edge_weights}

    chord_info = chord_chart_info(subG,list(subG.nodes()))
    summary_info = summary_data(subG)

    result = {"nodeList": nodes, "edgeList": edges, "nodes_info": nodes_info, "edges_info": edges_info, "chord_info": chord_info, "summary_info": summary_info}
    return result, subG