from flask import Flask, jsonify, request
from flask_cors import cross_origin
import pandas as pd
import networkx as nx

from finalFunction import subg_mining
from clueRelated import clue_projection_info,clue_comparision_supporter
from corePath import core_link
from subGraphMining import subg_info_neighbor

app = Flask(__name__)

# 导入数据
node_ = pd.read_csv('./data/Node.csv', encoding='utf-8', header=0)
link_ = pd.read_csv('./data/Link.csv', encoding='utf-8')

# 取第一个数据查看数据导入结果
# print(link_.iloc[0,:])

# 将DataFrame转为字典
nodeDict = node_.to_dict("records")
linkDict = link_.to_dict("records")

# 编码权重
type_list = {'Domain': 3, 'IP': 4, 'Cert': 4, 'Whois_Name': 2, 'Whois_Phone': 2, 'Whois_Email': 2, 'IP_C': 1, 'ASN': 1,
             ' ': 0}
link_weight = {'e_d2d_diff': 4, 'e_d2d_same': 4, 'r_cert': 4, 'r_subdomain': 4, 'r_request_jump': 4, 'r_dns_a': 4,
               'r_whois_name': 3, 'r_whois_email': 3, 'r_whois_phone': 3, 'r_cert_chain': 2, 'r_cname': 2, 'r_asn': 1,
               'r_cidr': 1}

# 设置节点权重，并将数据规范为networkx中创建图的格式
nodeList = []
for x in nodeDict:
    if x["industry"] == "[]":
        x["val"] = float(0 + type_list[x["type"]])
    else:
        x["val"] = float(len(x["industry"]) / 5 / 10 + type_list[x["type"]])
    nodeList.append((x["id"], x))

# 设置边的权重，并将数据规范为networkx中创建图的格式
linkList = []
for x in linkDict:
    x["weight"] = link_weight[x["relation"]]
    linkList.append((x["source"], x["target"], x))

# 用刚刚初始化的节点、边列表来创建无向图
G = nx.Graph()
G.add_nodes_from(nodeList)
G.add_edges_from(linkList)

for n in G.nodes():
    # if G.nodes[n]["type"] == "Cert" or G.nodes[n]["type"] == "IP":
    #     G.nodes[n]["type_weight"] = "critical"
    # elif G.nodes[n]["type"] == "Domain":
    #     G.nodes[n]["type_weight"] = "important"
    # elif G.nodes[n]["type"] == "Whois_Name" or G.nodes[n]["type"] == "Whois_Email" or G.nodes[n][
    #     "type"] == "Whois_Phone":
    #     G.nodes[n]["type_weight"] = "normal"
    # elif G.nodes[n]["type"] == "IP_C" or G.nodes[n]["type"] == "ASN":
    #     G.nodes[n]["type_weight"] = "weak"
    for i in G[n].items():
        critical, important, normal, weak = 0, 0, 0, 0
        neighbors_eis = {}
        if i[1]["relation"] == str("r_asn") or i[1]["relation"] == str("r_cidr"):
            weak += 1
        elif i[1]["relation"] == str("r_cname") or i[1]["relation"] == str("r_cert_chain"):
            normal += 1
        elif i[1]["relation"] == str("r_whois_email") or i[1]["relation"] == str("r_whois_name") or i[1][
            "relation"] == str("r_whois_phone"):
            important += 1
        elif i[1]["relation"] == str("r_cert") or i[1]["relation"] == str("r_subdomain") or i[1]["relation"] == str(
                "r_request_jump") or i[1]["relation"] == str("r_dns_a"):
            critical += 1
    neighbors_eis["critical"], neighbors_eis["important"], neighbors_eis["normal"], neighbors_eis[
        "weak"] = critical, important, normal, weak
    G.nodes[n]["edge_types"] = neighbors_eis
    G.nodes[n]["neighbors"] = len(list(G.neighbors(n)))

# 挖掘到的子图（有向图、无向图）
subGraph = nx.Graph()
subDiGraph = nx.DiGraph()

# 找线索（直接获取写死的数据）
cluePD = pd.read_csv('./data/Node50000_xy.csv', error_bad_lines=False, encoding='utf-8')
cluePartDictList = cluePD.to_dict("records")

@app.route("/subgraph/mining", methods=["POST"])
@cross_origin()
def subgraph_mining():
    data = request.get_json()
    clueidList = data.get("clueidList")
    constraintDict = data.get("constraintDict")
    edge_percent = constraintDict["edge_percent"]
    max_count = constraintDict["max_count"]
    global subGraph
    global subDiGraph
    subGResult,subGraph = subg_mining(G,clueidList,edge_percent,max_count)
    subDiGraph = nx.DiGraph(subGraph)
    return jsonify(subGResult)

@app.route("/clue/projection", methods=["POST"])
@cross_origin()
def clue_projection():
    data = request.get_json()
    max_count = data.get("max_count")
    edge_percent = data.get("edge_percent")
    global cluePartDictList
    clueResult = clue_projection_info(max_count, edge_percent,cluePartDictList)
    return jsonify(clueResult)

@app.route("/clue/comparision", methods=["POST"])
@cross_origin()
def clue_comparision():
    data = request.get_json()
    cluelist = data.get("cluelist")
    clueCompareResult = clue_comparision_supporter(G,cluelist,cluePD)
    return jsonify(clueCompareResult)

@app.route("/core/path", methods=["POST"])
@cross_origin()
def core_path():
    data = request.get_json()
    nodes = data.get("nodes")
    all_node, all_link = core_link(subDiGraph, nodes)
    result = {"all_node":all_node,"all_link":all_link}
    return jsonify(result)

@app.route("/subgraph/info/neighbor", methods=["POST"])
@cross_origin()
def subgraph_info_neighbor():
    data = request.get_json()
    id = data.get("id")
    myResult = subg_info_neighbor(id,subGraph)
    # print(myResult)
    return jsonify(myResult)


if __name__ == '__main__':
    app.run()
