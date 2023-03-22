# (对返回线索的统计)节点信息统计：类型
def edge_info_statistic_type(edge_list):
    err = 0
    edgeListDict = {"r_cert": [], "r_subdomain": [], "r_request_jump": [], "r_dns_a": [], "r_whois_name": [],
                    "r_whois_email": [], "r_whois_phone": [], "r_cert_chain": [], "r_cname": [], "r_asn": [],
                    "r_cidr": []}
    for t in edge_list:
        if t["relation"] == "r_cert":
            edgeListDict["r_cert"].append(t["edge_draw_id"])

        elif t["relation"] == "r_subdomain":
            edgeListDict["r_subdomain"].append(t["edge_draw_id"])

        elif t["relation"] == "r_request_jump":
            edgeListDict["r_request_jump"].append(t["edge_draw_id"])

        elif t["relation"] == "r_dns_a":
            edgeListDict["r_dns_a"].append(t["edge_draw_id"])

        elif t["relation"] == "r_whois_name":
            edgeListDict["r_whois_name"].append(t["edge_draw_id"])

        elif t["relation"] == "r_whois_email":
            edgeListDict["r_whois_email"].append(t["edge_draw_id"])

        elif t["relation"] == "r_whois_phone":
            edgeListDict["r_whois_phone"].append(t["edge_draw_id"])

        elif t["relation"] == "r_cert_chain":
            edgeListDict["r_cert_chain"].append(t["edge_draw_id"])

        elif t["relation"] == "r_cname":
            edgeListDict["r_cname"].append(t["edge_draw_id"])

        elif t["relation"] == "r_asn":
            edgeListDict["r_asn"].append(t["edge_draw_id"])

        elif t["relation"] == "r_cidr":
            edgeListDict["r_cidr"].append(t["edge_draw_id"])

        else:
            err = err + 1

    types = []
    for dt, de in edgeListDict.items():
        mydict = {"type": dt, "num": len(de), "edges": de}
        types.append(mydict)

    return types


# (对返回线索的统计)节点信息统计：权重分布
def edge_info_statistic_weight(edge_list):
    err = 0
    edgeListDict = {"critical": [], "important": [], "normal": [], "weak": []}
    for t in edge_list:
        if t["weight"] == 4:
            edgeListDict["critical"].append(t["edge_draw_id"])

        elif t["weight"] == 3:
            edgeListDict["important"].append(t["edge_draw_id"])

        elif t["weight"] == 2:
            edgeListDict["normal"].append(t["edge_draw_id"])

        elif t["weight"] == 1:
            edgeListDict["weak"].append(t["edge_draw_id"])

        else:
            err = err + 1

    weights = []
    for dt, de in edgeListDict.items():
        mydict = {"type": dt, "num": len(de), "edges": de}
        weights.append(mydict)

    return weights