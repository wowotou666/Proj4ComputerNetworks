#### Dynamic Link monitoring 

For this part we implemented the roundtrip latency. we deployed two geni sides, each have 2 vm inside. The detail configuration is in the test_geni config 
file. The four nodes we used are pcvm3-21.instageni.maxgigapop.net | pcvm4-11.geni.case.edu | pcvm5-23.geni.case.edu | pcvm2-15.instageni.maxgigapop.net. We 
set up two clients to connect with each other on node 1 and node 4. These two nodes are not directly connect with each other but through node 3 and node 2.
Base on the roundtrip latency, these two clients are able to switch between different route to comminicate with each other. So, sometime the path is 4-3-1
and sometime the path is 4-2-1 base on the roundtrip latency.
