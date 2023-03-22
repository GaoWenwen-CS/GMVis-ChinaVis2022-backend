from nodeInfo import node_info_statistic_neighbors,node_info_statistic_type,node_info_statistic_weight,node_info_statistic_edge_types
from subGraphMining import node_mining

clue_type_weight = {'Domain': "important", 'IP': "critical", 'Cert': "critical", 'Whois_Name': "normal", 'Whois_Phone': "normal", 'Whois_Email': "normal", 'IP_C': "weak", 'ASN': "weak"}

def clue_projection_info(max_count, edge_percent, clueList):
    mynodes = []
    count = 0
    for i in clueList:
        if type(i["edge_types"]) == type("s"):
            i["edge_types"] = eval(i["edge_types"])
        if sum(i["edge_types"].values()) == 0:
            perct = 0
        else:
            perct = (i["edge_types"]["critical"] + i["edge_types"]["important"]) / sum(i["edge_types"].values())

        if perct >= edge_percent:
            mynodes.append(i)
            count = count + 1

        if count >= max_count:
            break

    nodes = []
    for n in mynodes:
        if sum(n["edge_types"].values()) == 0:
            perct = 0
        else:
            perct = (n["edge_types"]["critical"] + n["edge_types"]["important"]) / sum(n["edge_types"].values())

        n["percent"] = perct

        x = round(n["x"], 3)
        y = round(n["y"], 3)
        pos = [x, y]
        mydict = {"id": n["id"], "node_draw_id": n["node_draw_id"], "type": n["type"], "industry": n["industry"],
                  "pos": pos,
                  "weight": n["weight"], "edge_types": n["edge_types"], "neighbors": n["neighbors"],
                  "percent": n["percent"], "type_weight": clue_type_weight[n["type"]]}
        nodes.append(mydict)

    types = node_info_statistic_type(mynodes)
    weights = node_info_statistic_weight(mynodes)
    edge_types = node_info_statistic_edge_types(mynodes)
    neighbors = node_info_statistic_neighbors(mynodes)

    myresult = {"nodes": nodes,
                "node_info": {"types": types, "weights": weights, "edge_types": edge_types, "neighbors": neighbors}}
    return myresult



def subg_mining_for_clue_projection(oriG,clue):
    jump1,jump2,jump3 = node_mining(oriG,clue,0.8,2)
    l = list(set(jump1+jump2+jump3+clue))
    return l


# def clue_comparision_supporter(oriG,cluelist):
#     clue_subg_list = []
#     for i in cluelist:
#         l = subg_mining_for_clue_projection(oriG,[i])
#         clue_subg_list.append(l)
#
#     nodes = []
#     edges = []
#     for i in range(len(clue_subg_list)):
#         node_item = {"id": cluelist[i], "size": len(clue_subg_list[i]), "sub_graph_nodes": clue_subg_list[i]}
#         nodes.append(node_item)
#         for j in range(len(clue_subg_list) - i - 1):
#             j = j + i + 1
#             slen = len(clue_subg_list[i])
#             tlen = len(clue_subg_list[j])
#             colen = (slen + tlen) - (len(list(set(clue_subg_list[i] + clue_subg_list[j]))))
#             edge_item = {"source": cluelist[i], "target": cluelist[j], "co_node_num": colen}
#             edges.append(edge_item)
#
#     result = {"nodes":nodes,"edges":edges}
#     return result

def clue_comparision_supporter(oriG,cluelist,clue_pd):
    clue_subg_list = []
    for i in cluelist:
        l = subg_mining_for_clue_projection(oriG,[i])
        clue_subg_list.append(l)

    nodes = []
    edges = []
    for i in range(len(clue_subg_list)):
        clue_i = clue_pd[clue_pd.id == cluelist[i]].to_dict("records")
        node_item = {"node_draw_id": clue_i[0]["node_draw_id"], "size": len(clue_subg_list[i]),"pos":[round(clue_i[0]["x"],3),round(clue_i[0]["y"],3)]}
        nodes.append(node_item)
        for j in range(len(clue_subg_list) - i - 1):
            j = j + i + 1
            slen = len(clue_subg_list[i])
            tlen = len(clue_subg_list[j])
            colen = (slen + tlen) - (len(list(set(clue_subg_list[i] + clue_subg_list[j]))))
            clue_j = clue_pd[clue_pd.id == cluelist[j]].to_dict("records")
            edge_item = {"source": [round(clue_i[0]["x"],3),round(clue_i[0]["y"],3)],"source_draw_id":clue_i[0]["node_draw_id"], "target":[round(clue_j[0]["x"],3),round(clue_j[0]["y"],3)],"target_draw_id":clue_j[0]["node_draw_id"], "co_node_num": colen}
            edges.append(edge_item)

    result = {"nodes":nodes,"edges":edges}
    return result