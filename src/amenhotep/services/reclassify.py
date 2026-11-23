"""Re-run identification on data already collected (no network traffic).

Use after editing rules (`os_rules.yaml`), updating the vendor lists, or improving the classifier.
Manual edits stay protected because they are locked fields.
"""

from __future__ import annotations

from amenhotep.services import identity
from amenhotep.services.scan import merge_by_ip
from amenhotep.store.repo import Repository


def reclassify(repo: Repository) -> int:
    """Re-resolve every host of the latest finished scan. Returns the number of hosts."""
    pairs = repo.latest_scan_observations()
    hostnames = {o.ip: h for o, h in pairs if o.ip and h}
    merged = merge_by_ip([o for o, _ in pairs])
    for obs in merged:
        obs.hostname = obs.hostname or hostnames.get(obs.ip or "")
        identity.resolve(repo, obs)
    repo.commit()
    return len(merged)
