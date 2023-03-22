def subgraph_edge_statistics(graph):
    '''
    输入子图:graph
    输出子图每个边信息，对应子图挖掘API的节边列表
   {'edge_draw_id': 'E0000254',
    'source': 'Domain_6bdbb6ba871f392b98bffb695e0e9c3d542625c7308ec80e57a8e2582bbc11fd',
    'target': 'Whois_Name_d93c941eef173511e77515af6861025e9a2a52d597e27bf1825961c2690e66cd',
    'relation': 'r_whois_name',
    'weight': 3,
    'draw_sid': 'N0000157',
    'draw_tid': 'N0000135'}
    '''
    edges_list = []
    for n in graph.edges().items():
        edges_list.append(n[1])

    return edges_list

def subgraph_node_statistics(graph):
    '''
    无向图，输出的信息来自所挖掘的子图
    输入子图:graph
    输出子图每个节点信息，对应子图挖掘API的节点列表
   {'id': 'Domain_6bdbb6ba871f392b98bffb695e0e9c3d542625c7308ec80e57a8e2582bbc11fd',
    'node_draw_id': 'N0000157',
    'type': 'Domain',
    'industry': '[]',
    'weight': 3.04,
    'edge_types': {'critical': 4, 'important': 2, 'normal': 0, 'weak': 0},
    'neighbors': 6}
    '''
    node_eis_num = []
    for n in graph.nodes():

        if len(graph.nodes(data=True)[n]) != 0:

            Dict = {}
            neighbors_eis = {}
            critical, important, normal, weak = 0, 0, 0, 0

            Dict["id"] = n
            Dict["node_draw_id"] = graph.nodes(data=True)[n]["node_draw_id"]
            Dict["type"] = graph.nodes(data=True)[n]["type"]
            Dict["industry"] = graph.nodes(data=True)[n]["industry"]
            Dict["weight"] = graph.nodes(data=True)[n]["val"]

            for i in graph[n].items():
                if i[1]["relation"] == str("r_asn") or i[1]["relation"] == str("r_cidr"):
                    weak += 1
                elif i[1]["relation"] == str("r_cname") or i[1]["relation"] == str("r_cert_chain"):
                    normal += 1
                elif i[1]["relation"] == str("r_whois_email") or i[1]["relation"] == str("r_whois_name") or i[1][
                    "relation"] == str("r_whois_phone"):
                    important += 1
                elif i[1]["relation"] == str("r_cert") or i[1]["relation"] == str("r_subdomain") or i[1][
                    "relation"] == str("r_request_jump") or i[1]["relation"] == str("r_dns_a"):
                    critical += 1
            neighbors_eis["critical"], neighbors_eis["important"], neighbors_eis["normal"], neighbors_eis[
                "weak"] = critical, important, normal, weak
            Dict["edge_types"] = neighbors_eis
            Dict['neighbors'] = len(list(graph.neighbors(n)))
            node_eis_num.append(Dict)

    return node_eis_num