SOURCES = main.c util.c read_netlist.c read_arch.c place.c route.c draw.c graphics.c stats.c segment_stats.c rr_graph.c rr_graph2.c rr_graph_sbox.c rr_graph_util.c rr_graph_timing_params.c rr_graph_area.c check_rr_graph.c check_route.c hash.c read_place.c
OUTPUT = vpr
TEMPFILES = placed.out routed.out
#COMMAND = vpr circuit.net fpga.arch placed.out routed.out -nx 92 -ny 92

COMMAND = vpr testdata/net.in testdata/arch.in placed.out routed.out -nodisp -place_only -init_t 5 -exit_t 0.005 -alpha_t 0.9412 -inner_num 2

-include ../Makefile.config
