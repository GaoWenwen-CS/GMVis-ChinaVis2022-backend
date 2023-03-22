import itertools
import json
import networkx as nx

# 找两个节点的所有路径
def s2t_paths(graph ,startnode ,endnode ,digraph):

    if digraph:
        paths = list(nx.all_simple_paths(graph, startnode, endnode))  # all_shortest_paths, all_simple_paths
    else:
        paths = list(nx.all_shortest_paths(graph, startnode, endnode))

    nl = []
    ll = []
    dict_nodes = []
    dict_links = []
    for i in range(len(paths)):
        for j in paths[i]:
            if j not in nl:
                dict_nodes.append(json.dumps(graph.nodes(data = True)[j]))
                nl.append(j)

        for k in range(len(paths[i] ) -1):
            subs = paths[i][k]
            subt = paths[i][ k +1]
            if (subs ,subt) not in ll:
                dict_links.append(json.dumps(graph[subs][subt]))
                ll.append((subs ,subt))

    return dict_nodes ,dict_links

def node2node_path(graph ,s1 ,s2 ,digraph):

    node_L1 ,link_L1 = s2t_paths(graph ,s1 ,s2, digraph)  # 正向

    node_L2 ,link_L2 = s2t_paths(graph ,s2 ,s1, digraph)  # 反向

    n ,l = node_L1 +node_L2 ,link_L1 +link_L2

    if digraph:
        n ,l = n ,l

    else:
        n = n[:int(len(n ) /2)]
        l = l[:int(len(l ) /2)]

    return n ,l

def core_link(graph ,node_list ,digraph = True):
    com = itertools.combinations(node_list ,2)
    all_node ,all_link = [] ,[]
    out_node ,out_link = [] ,[]
    for pair in com:
        s1 ,s2 = pair[0] ,pair[1]
        n ,l = node2node_path(graph ,s1 ,s2 ,digraph)
        all_node = all_node + n
        all_link = all_link + l

    for i in set(all_node):
        out_node.append(json.loads(i))
    for j in set(all_link):
        out_link.append(json.loads(j))
    return out_node ,out_link