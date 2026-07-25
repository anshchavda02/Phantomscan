const d3 = require('d3');
const d3_data = {"nodes": [{"id": "hackthissite.org", "name": "hackthissite.org", "group": 1, "radius": 20, "type": "target"}, {"id": "137.74.187.100", "name": "137.74.187.100", "group": 2, "radius": 15, "type": "ip"}, {"id": "137.74.187.100:80", "name": "Port 80", "group": 3, "radius": 10, "type": "service"}, {"id": "137.74.187.100:443", "name": "Port 443", "group": 3, "radius": 10, "type": "service"}, {"id": "137.74.187.101", "name": "137.74.187.101", "group": 2, "radius": 15, "type": "ip"}, {"id": "137.74.187.102", "name": "137.74.187.102", "group": 2, "radius": 15, "type": "ip"}, {"id": "137.74.187.103", "name": "137.74.187.103", "group": 2, "radius": 15, "type": "ip"}, {"id": "137.74.187.104", "name": "137.74.187.104", "group": 2, "radius": 15, "type": "ip"}, {"id": "api.hackthissite.org", "name": "api.hackthissite.org", "group": 4, "radius": 12, "type": "subdomain"}, {"id": "git.hackthissite.org", "name": "git.hackthissite.org", "group": 4, "radius": 12, "type": "subdomain"}, {"id": "status.hackthissite.org", "name": "status.hackthissite.org", "group": 4, "radius": 12, "type": "subdomain"}, {"id": "www.hackthissite.org", "name": "www.hackthissite.org", "group": 4, "radius": 12, "type": "subdomain"}], "links": [{"source": "hackthissite.org", "target": "137.74.187.100", "value": 2}, {"source": "137.74.187.100", "target": "137.74.187.100:80", "value": 1}, {"source": "137.74.187.100", "target": "137.74.187.100:443", "value": 1}, {"source": "hackthissite.org", "target": "137.74.187.101", "value": 2}, {"source": "hackthissite.org", "target": "137.74.187.102", "value": 2}, {"source": "hackthissite.org", "target": "137.74.187.103", "value": 2}, {"source": "hackthissite.org", "target": "137.74.187.104", "value": 2}, {"source": "hackthissite.org", "target": "api.hackthissite.org", "value": 1}, {"source": "hackthissite.org", "target": "git.hackthissite.org", "value": 1}, {"source": "hackthissite.org", "target": "status.hackthissite.org", "value": 1}, {"source": "hackthissite.org", "target": "www.hackthissite.org", "value": 1}]};
const nodes = d3_data.nodes;
const links = d3_data.links;
try {
    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(60))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(800 / 2, 600 / 2))
        .force('collide', d3.forceCollide().radius(20));
    console.log('Simulation created successfully');
} catch(e) {
    console.error('ERROR:', e);
}
