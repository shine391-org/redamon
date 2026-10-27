"""IP attribution graph write: each IP's ownership tag (plan 11.3).

Writes, on the EXISTING tenant-scoped IP node only (never creates one):
  - ownership           shared_edge | dedicated | unknown, never "not ours"
  - ownership_reasons   sorted list of short phrases
  - current_dns_names   how many names in the run's DNS resolve to the IP
  - default_cert_names  sorted CN + SANs of the certificate presented without
                        SNI, when the handshake read one
  - a shared edge's CDN tag: is_cdn, cdn_name, cdn_source 'ip_attribution'

No updated_at: a tag is not a sighting, and the IP's other writers own that stamp.
"""

_TAGS = ("shared_edge", "dedicated", "unknown")
_PROPS = ("ownership", "ownership_reasons", "current_dns_names", "default_cert_names")


class IpAttributionMixin:
    def update_graph_from_ip_attribution(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {"ips_tagged": 0, "errors": []}
        by_ip = ((recon_data or {}).get("ip_attribution") or {}).get("by_ip") or {}
        if not isinstance(by_ip, dict) or not by_ip:
            return stats

        with self.driver.session() as session:
            for ip, entry in by_ip.items():
                if not ip or not isinstance(entry, dict) or entry.get("ownership") not in _TAGS:
                    continue
                props = {k: entry[k] for k in _PROPS if entry.get(k) is not None}
                edge_cdn = entry.get("cdn_name") if entry["ownership"] == "shared_edge" else None
                try:
                    row = session.run(
                        """
                        MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                        WITH i, coalesce(i.is_cdn, false) AS already_tagged
                        SET i += $props,
                            i.cdn_source = CASE WHEN $edge_cdn IS NOT NULL AND NOT already_tagged
                                                THEN 'ip_attribution' ELSE i.cdn_source END,
                            i.is_cdn = CASE WHEN $edge_cdn IS NOT NULL THEN true ELSE i.is_cdn END,
                            i.cdn_name = CASE WHEN $edge_cdn IS NOT NULL
                                              THEN coalesce(i.cdn_name, $edge_cdn) ELSE i.cdn_name END
                        RETURN count(i) AS matched
                        """,
                        ip=ip, props=props, edge_cdn=edge_cdn, uid=user_id, pid=project_id,
                    ).single()
                    if row and row["matched"]:
                        stats["ips_tagged"] += 1
                except Exception as e:
                    stats["errors"].append(f"ip_attribution {ip}: {e}")

        print(f"[+][graph-db] IP attribution: {stats['ips_tagged']} IP(s) tagged")
        if stats["errors"]:
            print(f"[!][graph-db] IP attribution: {len(stats['errors'])} write(s) failed, "
                  f"first: {stats['errors'][0]}")
        return stats
