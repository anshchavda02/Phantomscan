const js = require('jsdom');
const { JSDOM } = js;
const dom = new JSDOM('<div id="attack-map-wrapper"><div id="map-tooltip"></div><svg id="attack-map-svg"></svg><button id="map-zoom-in"></button><button id="map-zoom-out"></button><button id="map-reset"></button></div>');
global.document = dom.window.document;

const d3 = require('d3');
const state = { d3Data: {"nodes": [{"id": "hackthissite.org", "name": "hackthissite.org", "group": 1, "radius": 20, "type": "target"}, {"id": "137.74.187.100", "name": "137.74.187.100", "group": 2, "radius": 15, "type": "ip"}, {"id": "137.74.187.100:80", "name": "Port 80", "group": 3, "radius": 10, "type": "service"}, {"id": "137.74.187.100:443", "name": "Port 443", "group": 3, "radius": 10, "type": "service"}, {"id": "137.74.187.101", "name": "137.74.187.101", "group": 2, "radius": 15, "type": "ip"}, {"id": "137.74.187.102", "name": "137.74.187.102", "group": 2, "radius": 15, "type": "ip"}, {"id": "137.74.187.103", "name": "137.74.187.103", "group": 2, "radius": 15, "type": "ip"}, {"id": "137.74.187.104", "name": "137.74.187.104", "group": 2, "radius": 15, "type": "ip"}, {"id": "api.hackthissite.org", "name": "api.hackthissite.org", "group": 4, "radius": 12, "type": "subdomain"}, {"id": "git.hackthissite.org", "name": "git.hackthissite.org", "group": 4, "radius": 12, "type": "subdomain"}, {"id": "status.hackthissite.org", "name": "status.hackthissite.org", "group": 4, "radius": 12, "type": "subdomain"}, {"id": "www.hackthissite.org", "name": "www.hackthissite.org", "group": 4, "radius": 12, "type": "subdomain"}], "links": [{"source": "hackthissite.org", "target": "137.74.187.100", "value": 2}, {"source": "137.74.187.100", "target": "137.74.187.100:80", "value": 1}, {"source": "137.74.187.100", "target": "137.74.187.100:443", "value": 1}, {"source": "hackthissite.org", "target": "137.74.187.101", "value": 2}, {"source": "hackthissite.org", "target": "137.74.187.102", "value": 2}, {"source": "hackthissite.org", "target": "137.74.187.103", "value": 2}, {"source": "hackthissite.org", "target": "137.74.187.104", "value": 2}, {"source": "hackthissite.org", "target": "api.hackthissite.org", "value": 1}, {"source": "hackthissite.org", "target": "git.hackthissite.org", "value": 1}, {"source": "hackthissite.org", "target": "status.hackthissite.org", "value": 1}, {"source": "hackthissite.org", "target": "www.hackthissite.org", "value": 1}]} };
try {
// Basic D3.js Force Directed Graph initialization
    // The actual data is loaded from state.d3Data
    if (!state.d3Data || !state.d3Data.nodes || state.d3Data.nodes.length === 0) {
        document.getElementById('attack-map-wrapper').innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-muted);">Attack surface map data not available</div>';
        return;
    }

    const container = document.getElementById('attack-map-wrapper');
    const width = container.clientWidth;
    const height = container.clientHeight;
    
    try {
        const svg = d3.select("#attack-map-svg")
            .attr("viewBox", [0, 0, width, height]);
            
        const g = svg.append("g");
    
    // Zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on("zoom", (event) => g.attr("transform", event.transform));
    svg.call(zoom);
    
    // Controls
    document.getElementById('map-zoom-in').addEventListener('click', () => svg.transition().call(zoom.scaleBy, 1.3));
    document.getElementById('map-zoom-out').addEventListener('click', () => svg.transition().call(zoom.scaleBy, 0.7));
    document.getElementById('map-reset').addEventListener('click', () => svg.transition().call(zoom.transform, d3.zoomIdentity.translate(width/2, height/2).scale(1)));
    
    const nodes = state.d3Data.nodes;
    const links = state.d3Data.links;
    
    // Simulation
    const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(links).id(d => d.id).distance(60))
        .force("charge", d3.forceManyBody().strength(-200))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collide", d3.forceCollide().radius(20));

    // Links
    const link = g.append("g")
        .attr("stroke", "var(--border-light)")
        .attr("stroke-opacity", 0.6)
        .selectAll("line")
        .data(links)
        .join("line")
        .attr("stroke-width", d => Math.sqrt(d.value || 1));

    // Nodes
    const tooltip = document.getElementById('map-tooltip');
    
    const node = g.append("g")
        .selectAll("path")
        .data(nodes)
        .join("path")
        .attr("d", d => {
            // Different shapes based on type
            if (d.type === 'vulnerability') {
                return d3.symbol().type(d3.symbolTriangle).size(150)();
            } else if (d.type === 'chain') {
                return d3.symbol().type(d3.symbolStar).size(200)();
            }
            return d3.symbol().type(d3.symbolCircle).size(d.type === 'target' ? 400 : 100)();
        })
        .attr("fill", d => {
            if (d.type === 'target') return "var(--accent)";
            if (d.type === 'subdomain') return "var(--accent2)";
            if (d.type === 'ip') return "var(--mod-network)";
            if (d.type === 'vulnerability') return "var(--crit)";
            if (d.type === 'chain') return "var(--crit)";
            return "var(--info)";
        })
        .attr("stroke", "var(--bg)")
        .attr("stroke-width", 1.5)
        .call(drag(simulation));

    // Labels
    const label = g.append("g")
        .selectAll("text")
        .data(nodes)
        .join("text")
        .attr("dy", 12)
        .attr("dx", 0)
        .attr("text-anchor", "middle")
        .text(d => d.name)
        .style("font-size", "10px")
        .style("fill", "var(--text)")
        .style("pointer-events", "none")
        .style("opacity", d => d.type === 'target' ? 1 : 0.7);

    // Hover effects
    node.on("mouseover", (event, d) => {
        tooltip.innerHTML = `<strong>${d.name}</strong><br><span style="color:var(--text-muted);font-size:10px;">Type: ${d.type}</span>`;
        tooltip.style.opacity = 1;
        tooltip.style.left = (event.pageX + 15) + "px";
        tooltip.style.top = (event.pageY - 15) + "px";
        
        // Highlight connected
        const connected = new Set();
        connected.add(d.id);
        link.style("stroke", l => {
            if (l.source.id === d.id || l.target.id === d.id) {
                connected.add(l.source.id);
                connected.add(l.target.id);
                return "var(--accent-light)";
            }
            return "var(--border)";
        });
        node.style("opacity", n => connected.has(n.id) ? 1 : 0.2);
        label.style("opacity", n => connected.has(n.id) ? 1 : 0);
    })
    .on("mouseout", () => {
        tooltip.style.opacity = 0;
        link.style("stroke", "var(--border-light)");
        node.style("opacity", 1);
        label.style("opacity", d => d.type === 'target' ? 1 : 0.7);
    });

    simulation.on("tick", () => {
        link
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);

        node.attr("transform", d => `translate(${d.x},${d.y})`);
        label.attr("x", d => d.x).attr("y", d => d.y + 12);
    });
    
    // Initial center zoom
    svg.call(zoom.transform, d3.zoomIdentity.translate(width/2, height/2).scale(1));

    function drag(simulation) {
        function dragstarted(event) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }
        function dragged(event) {
            event.subject.fx = event.x;
            event.subject.fy = event.y;
        }
        function dragended(event) {
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
        }
        return d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended);
    }
    
    } catch (e) {
        console.error("D3 Attack Map generation failed:", e);
        container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--crit);text-align:center;padding:20px;">Failed to render Attack Map.<br>Check console for errors (D3.js might be blocked by browser extensions).</div>';
    }

console.log('D3 logic completed without error');
} catch(e) {
console.error('D3 Error caught:', e);
}
