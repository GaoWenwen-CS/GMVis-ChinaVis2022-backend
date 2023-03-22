import re


# (对返回线索的统计)节点信息统计：类型
def node_info_statistic_type(node_list):
    err = 0
    nodeListDict = {"IP": [], "Domain": [], "Cert": [], "Whois_Name": [], "Whois_Phone": [], "Whois_Email": [],
                    "IP_C": [], "ASN": []}
    domainListDict = {"A": [], "B": [], "C": [], "D": [], "E": [], "F": [], "G": [], "H": [], "I": []}
    for t in node_list:
        if t["type"] == "IP":
            nodeListDict["IP"].append(t["node_draw_id"])

        elif t["type"] == "Domain":
            nodeListDict["Domain"].append(t["node_draw_id"])

            if re.search("A", t["industry"]) != None:
                domainListDict["A"].append(t["node_draw_id"])

            elif re.search("B", t["industry"]) != None:
                domainListDict["B"].append(t["node_draw_id"])

            elif re.search("C", t["industry"]) != None:
                domainListDict["C"].append(t["node_draw_id"])

            elif re.search("D", t["industry"]) != None:
                domainListDict["D"].append(t["node_draw_id"])

            elif re.search("E", t["industry"]) != None:
                domainListDict["E"].append(t["node_draw_id"])

            elif re.search("F", t["industry"]) != None:
                domainListDict["F"].append(t["node_draw_id"])

            elif re.search("G", t["industry"]) != None:
                domainListDict["G"].append(t["node_draw_id"])

            elif re.search("H", t["industry"]) != None:
                domainListDict["H"].append(t["node_draw_id"])

            else:
                domainListDict["I"].append(t["node_draw_id"])

        elif t["type"] == "Cert":
            nodeListDict["Cert"].append(t["node_draw_id"])

        elif t["type"] == "Whois_Name":
            nodeListDict["Whois_Name"].append(t["node_draw_id"])

        elif t["type"] == "Whois_Phone":
            nodeListDict["Whois_Phone"].append(t["node_draw_id"])

        elif t["type"] == "Whois_Email":
            nodeListDict["Whois_Email"].append(t["node_draw_id"])

        elif t["type"] == "IP_C":
            nodeListDict["IP_C"].append(t["node_draw_id"])

        elif t["type"] == "ASN":
            nodeListDict["ASN"].append(t["node_draw_id"])

        else:
            err = err + 1

    IPDict = {"type": "IP", "num": len(nodeListDict["IP"]), "nodes": nodeListDict["IP"]}
    industryDictA = {"type": "A", "des": "涉黄", "num": len(domainListDict["A"]), "nodes": domainListDict["A"]}
    industryDictB = {"type": "B", "des": "涉赌", "num": len(domainListDict["B"]), "nodes": domainListDict["B"]}
    industryDictC = {"type": "C", "des": "诈骗", "num": len(domainListDict["C"]), "nodes": domainListDict["C"]}
    industryDictD = {"type": "D", "des": "涉毒", "num": len(domainListDict["D"]), "nodes": domainListDict["D"]}
    industryDictE = {"type": "E", "des": "涉枪", "num": len(domainListDict["E"]), "nodes": domainListDict["E"]}
    industryDictF = {"type": "F", "des": "黑客", "num": len(domainListDict["F"]), "nodes": domainListDict["F"]}
    industryDictG = {"type": "G", "des": "非法交易平台", "num": len(domainListDict["G"]), "nodes": domainListDict["G"]}
    industryDictH = {"type": "H", "des": "非法支付平台", "num": len(domainListDict["H"]), "nodes": domainListDict["H"]}
    industryDictI = {"type": "I", "des": "其他", "num": len(domainListDict["I"]), "nodes": domainListDict["I"]}
    industryList = [industryDictA, industryDictB, industryDictC, industryDictD, industryDictE, industryDictF,
                    industryDictG, industryDictH, industryDictI]
    DomainDict = {"type": "Domain", "num": len(nodeListDict["Domain"]), "nodes": nodeListDict["Domain"],
                  "industry": industryList}
    CertDict = {"type": "Cert", "num": len(nodeListDict["Cert"]), "nodes": nodeListDict["Cert"]}
    Whois_NameDict = {"type": "Whois_Name", "num": len(nodeListDict["Whois_Name"]), "nodes": nodeListDict["Whois_Name"]}
    Whois_PhoneDict = {"type": "Whois_Phone", "num": len(nodeListDict["Whois_Phone"]),
                       "nodes": nodeListDict["Whois_Phone"]}
    Whois_EmailDict = {"type": "Whois_Email", "num": len(nodeListDict["Whois_Email"]),
                       "nodes": nodeListDict["Whois_Email"]}
    IP_CDict = {"type": "IP_C", "num": len(nodeListDict["IP_C"]), "nodes": nodeListDict["IP_C"]}
    ASNDict = {"type": "ASN", "num": len(nodeListDict["ASN"]), "nodes": nodeListDict["ASN"]}

    types = [IPDict, DomainDict, CertDict, Whois_NameDict, Whois_PhoneDict, Whois_EmailDict, IP_CDict, ASNDict]

    return types


# (对返回线索的统计)节点信息统计：权重分布
def node_info_statistic_weight(node_list):
    err = 0
    nodeListDict = {"critical": [], "important": [], "normal": [], "weak": []}
    for t in node_list:
        if t["type"] == "IP":
            nodeListDict["critical"].append(t["node_draw_id"])

        elif t["type"] == "Cert":
            nodeListDict["critical"].append(t["node_draw_id"])

        elif t["type"] == "Domain":
            nodeListDict["important"].append(t["node_draw_id"])

        elif t["type"] == "Whois_Name":
            nodeListDict["normal"].append(t["node_draw_id"])

        elif t["type"] == "Whois_Phone":
            nodeListDict["normal"].append(t["node_draw_id"])

        elif t["type"] == "Whois_Email":
            nodeListDict["normal"].append(t["node_draw_id"])

        elif t["type"] == "IP_C":
            nodeListDict["weak"].append(t["node_draw_id"])

        elif t["type"] == "ASN":
            nodeListDict["weak"].append(t["node_draw_id"])

        else:
            err = err + 1

    cDict = {"type": "critical", "num": len(nodeListDict["critical"]), "nodes": nodeListDict["critical"]}
    iDict = {"type": "important", "num": len(nodeListDict["important"]), "nodes": nodeListDict["important"]}
    nDict = {"type": "normal", "num": len(nodeListDict["normal"]), "nodes": nodeListDict["normal"]}
    wDict = {"type": "weak", "num": len(nodeListDict["weak"]), "nodes": nodeListDict["weak"]}
    weights = [cDict, iDict, nDict, wDict]

    return weights


# (对返回线索的统计)节点信息统计：包含边分布
def node_info_statistic_edge_types(node_list):
    err = 0
    sort_node_list = sorted(node_list, key=lambda n: (n["edge_types"]["critical"] + n["edge_types"]["important"]) / (
                sum(n["edge_types"].values()) + 1), reverse=False)
    m = (((sort_node_list[-1]["edge_types"]["critical"] + sort_node_list[-1]["edge_types"]["important"]) / sum(
        sort_node_list[-1]["edge_types"].values())) - 0.5) / 5

    nodeListDict = {"0,0.5": [], "0.5," + str(0.5 + m): [], str(0.5 + m) + "," + str(0.5 + 2 * m): [],
                    str(0.5 + 2 * m) + "," + str(0.5 + 3 * m): [], str(0.5 + 3 * m) + "," + str(0.5 + 4 * m): [],
                    str(0.5 + 4 * m) + "," + str(0.5 + 5 * m): []}

    # print(m)
    for t in node_list:
        if sum(t["edge_types"].values()) == 0:
            perct = 0
        else:
            perct = (t["edge_types"]["critical"] + t["edge_types"]["important"]) / sum(t["edge_types"].values())

        if perct <= 0.5:
            nodeListDict["0,0.5"].append(t["node_draw_id"])
        elif perct > 0.5 and perct <= (0.5 + m):
            nodeListDict["0.5," + str(0.5 + m)].append(t["node_draw_id"])

        elif perct > (0.5 + m) and perct <= (0.5 + 2 * m):
            nodeListDict[str(0.5 + m) + "," + str(0.5 + 2 * m)].append(t["node_draw_id"])

        elif perct > (0.5 + 2 * m) and perct <= (0.5 + 3 * m):
            nodeListDict[str(0.5 + 2 * m) + "," + str(0.5 + 3 * m)].append(t["node_draw_id"])

        elif perct > (0.5 + 3 * m) and perct <= (0.5 + 4 * m):
            nodeListDict[str(0.5 + 3 * m) + "," + str(0.5 + 4 * m)].append(t["node_draw_id"])

        elif perct > (0.5 + 4 * m) and perct <= (0.5 + 5 * m):
            nodeListDict[str(0.5 + 4 * m) + "," + str(0.5 + 5 * m)].append(t["node_draw_id"])

        else:
            err = err + 1

    edge_types = []
    for dt, dn in nodeListDict.items():
        m = dt.split(",")
        mydict = {"percent": [float(m[0]),float(m[1])], "des": "critical&important", "num": len(dn), "nodes": dn}
        edge_types.append(mydict)

    return edge_types


# (对返回线索的统计)节点信息统计：包含边分布
def node_info_statistic_neighbors(node_list):
    err = 0
    sort_node_list = sorted(node_list, key=lambda n: n["neighbors"], reverse=False)
    max_nb = sort_node_list[-1]["neighbors"] + (5 - sort_node_list[-1]["neighbors"] % 5)
    min_nb = sort_node_list[0]["neighbors"] - (sort_node_list[0]["neighbors"] % 5)
    #     m = (sort_node_list[-1]["neighbors"]-sort_node_list[0]["neighbors"])/5
    #     m = math.ceil(m)  #向上取整
    m = (max_nb - min_nb) // 5
    min_m = min_nb
    nodeListDict = {str(min_m) + "," + str(min_m + m): [], str(min_m + m) + "," + str(min_m + 2 * m): [],
                    str(min_m + 2 * m) + "," + str(min_m + 3 * m): [],
                    str(min_m + 3 * m) + "," + str(min_m + 4 * m): [],
                    str(min_m + 4 * m) + "," + str(min_m + 5 * m): []}

    for t in node_list:
        if t["neighbors"] <= min_m + m:
            nodeListDict[str(min_m) + "," + str(min_m + m)].append(t["node_draw_id"])

        elif t["neighbors"] > min_m + m and t["neighbors"] <= min_m + 2 * m:
            nodeListDict[str(min_m + m) + "," + str(min_m + 2 * m)].append(t["node_draw_id"])

        elif t["neighbors"] > min_m + 2 * m and t["neighbors"] <= min_m + 3 * m:
            nodeListDict[str(min_m + 2 * m) + "," + str(min_m + 3 * m)].append(t["node_draw_id"])

        elif t["neighbors"] > min_m + 3 * m and t["neighbors"] <= min_m + 4 * m:
            nodeListDict[str(min_m + 3 * m) + "," + str(min_m + 4 * m)].append(t["node_draw_id"])

        elif t["neighbors"] > min_m + 4 * m and t["neighbors"] <= min_m + 5 * m:
            nodeListDict[str(min_m + 4 * m) + "," + str(min_m + 5 * m)].append(t["node_draw_id"])

        else:
            err = err + 1

    neighbors = []
    for dt, dn in nodeListDict.items():
        m = dt.split(",")
        mydict = {"type": [int(m[0]),int(m[1])], "num": len(dn), "nodes": dn}
        neighbors.append(mydict)

    return neighbors

