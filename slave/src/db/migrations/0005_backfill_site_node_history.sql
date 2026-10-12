INSERT INTO waf_site_node_history (project_id, region_id, site_id, node_id)
SELECT site.project_id, site.region_id, assignment.site_id, assignment.node_id
FROM waf_site_nodes AS assignment
JOIN waf_sites AS site ON site.id = assignment.site_id
ON CONFLICT (site_id, node_id) DO NOTHING;
