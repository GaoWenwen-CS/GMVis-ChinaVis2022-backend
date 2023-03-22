def chord_chart_info(subg,nodes_list):
    SG = subg.subgraph(nodes_list)
    result = []
    for e,attr in SG.edges().items():
        source = attr["draw_sid"]
        target = attr["draw_tid"]
        weight = attr["weight"]
        dict_items = {"source":source,"target":target,"weight":weight}
        result.append(dict_items)
    return result