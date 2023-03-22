import networkx as nx

# 输入节点列表，获取该列表的一跳节点
from nodeInfo import node_info_statistic_type,node_info_statistic_edge_types,node_info_statistic_neighbors,node_info_statistic_weight
from edgeInfo import edge_info_statistic_type,edge_info_statistic_weight
from subGraphStatistic import subgraph_node_statistics,subgraph_edge_statistics
from chordInfo import chord_chart_info
from summaryInfo import summary_data


def one_jump_select(oriG, nodes_list, edge_percent, m=1):
    one_jump_list = []
    Result_edgeListDict = {"r_cert": [], "r_subdomain": [], "r_request_jump": [], "r_dns_a": [], "r_whois_name": [],
                           "r_whois_email": [], "r_whois_phone": [], "r_cert_chain": [], "r_cname": [], "r_asn": [],
                           "r_cidr": []}

    for n in nodes_list:
        edgeListDict = {"r_cert": [], "r_subdomain": [], "r_request_jump": [], "r_dns_a": [], "r_whois_name": [],
                        "r_whois_email": [], "r_whois_phone": [], "r_cert_chain": [], "r_cname": [], "r_asn": [],
                        "r_cidr": []}
        jump_list = []
        neighbor_list = []
        for n1, eattr1 in oriG[n].items():
            neighbor_list.append(n1)
            # 找核心节点的过滤条件
            if (oriG.nodes[n1]["edge_types"]["critical"] + oriG.nodes[n]["edge_types"]["important"]) / sum(
                    oriG.nodes[n]["edge_types"].values()) < edge_percent:
                continue

            if oriG.nodes[n1]["type"] == "IP":
                count = 0
                flag = 0
                for n2, eattr2 in oriG[n1].items():
                    if oriG.nodes[n2]["type"] == "Domain":
                        count = count + 1
                    if count >= 2:
                        flag = 1
                        break
                if flag == 1:
                    continue

            if eattr1["relation"] == "r_cert":
                edgeListDict["r_cert"].append(n1)

            elif eattr1["relation"] == "r_subdomain":
                edgeListDict["r_subdomain"].append(n1)

            elif eattr1["relation"] == "r_request_jump":
                edgeListDict["r_request_jump"].append(n1)

            elif eattr1["relation"] == "r_dns_a":
                edgeListDict["r_dns_a"].append(n1)

            elif eattr1["relation"] == "r_whois_name":
                edgeListDict["r_whois_name"].append(n1)

            elif eattr1["relation"] == "r_whois_email":
                edgeListDict["r_whois_email"].append(n1)

            elif eattr1["relation"] == "r_whois_phone":
                edgeListDict["r_whois_phone"].append(n1)

            elif eattr1["relation"] == "r_cert_chain":
                edgeListDict["r_cert_chain"].append(n1)

            elif eattr1["relation"] == "r_cname":
                edgeListDict["r_cname"].append(n1)

            elif eattr1["relation"] == "r_asn":
                edgeListDict["r_asn"].append(n1)

            elif eattr1["relation"] == "r_cidr":
                edgeListDict["r_cidr"].append(n1)

        for i, j in edgeListDict.items():
            if len(j) >= 10:
                mid_dict = dict(oriG.degree(j))
                avg = sum(mid_dict.values()) / len(j)
                mid_list = []
                mid_list = list(k for k, v in mid_dict.items() if v > avg * m)
                edgeListDict[i] = mid_list
                jump_list = jump_list + mid_list
            else:
                jump_list = jump_list + j

        if len(jump_list) == 0:
            m_dict = dict(oriG.degree(neighbor_list))
            m_list = max(m_dict, key=m_dict.get)
            one_jump_list.append(m_list)

        else:
            one_jump_list.extend(jump_list)
            Result_edgeListDict["r_cert"].extend(edgeListDict["r_cert"])
            Result_edgeListDict["r_subdomain"].extend(edgeListDict["r_subdomain"])
            Result_edgeListDict["r_request_jump"].extend(edgeListDict["r_request_jump"])
            Result_edgeListDict["r_dns_a"].extend(edgeListDict["r_dns_a"])
            Result_edgeListDict["r_whois_name"].extend(edgeListDict["r_whois_name"])
            Result_edgeListDict["r_whois_email"].extend(edgeListDict["r_whois_email"])
            Result_edgeListDict["r_whois_phone"].extend(edgeListDict["r_whois_phone"])
            Result_edgeListDict["r_cert_chain"].extend(edgeListDict["r_cert_chain"])
            Result_edgeListDict["r_cname"].extend(edgeListDict["r_cname"])
            Result_edgeListDict["r_asn"].extend(edgeListDict["r_asn"])
            Result_edgeListDict["r_cidr"].extend(edgeListDict["r_cidr"])

    return one_jump_list, Result_edgeListDict


# 节点挖掘
def node_mining(oriG,clue,edge_percent,m=1):
    jump1,edgeListDict1 = one_jump_select(oriG,clue,edge_percent,m)
    next_jump = []
    for x,y in edgeListDict1.items():
        if x=="r_asn" or x=="r_cidr":
            continue
        next_jump.extend(y)
    jump2,edgeListDict2 = one_jump_select(oriG,next_jump,edge_percent,m)
    next_jump = []
    for x,y in edgeListDict2.items():
        if x=="r_asn" or x=="r_cidr" or x=="r_cert_chain" or x=="r_cname":
            continue
        next_jump.extend(y)
    jump3,edgeListDict3 = one_jump_select(oriG,next_jump,edge_percent,m)
    return jump1,jump2,jump3


# 路径挖掘
def path_node_mining(oriG, clue):
    relation_st_node = []
    for i in range(len(clue)):
        for j in range(len(clue) - i - 1):
            j = j + i + 1
            for path in nx.all_shortest_paths(oriG, source=clue[i], target=clue[j]):
                relation_st_node.extend(path)
    #                 print(path)
    #                 for node in path:
    #                     if node not in relation_st_node:
    #                         relation_st_node.append(node)

    return relation_st_node


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
    print(result)
    return result, subG


# 给定一个节点id，返回该节点的邻居节点和邻居边列表
def subg_info_neighbor(nodeId,subH):
    nodes = []
    edges = []
    # a = list(subH[nodeId].items())
    for nbr,eattr in subH[nodeId].items():
        nodes.append(eattr["draw_sid"])
        nodes.append(eattr["draw_tid"])
        edges.append(eattr["edge_draw_id"])
    nodes = list(set(nodes))
    nodes.remove(subH.nodes(data=True)[nodeId]["node_draw_id"])
    result = {"nodes":nodes,"edges":edges}
    return result